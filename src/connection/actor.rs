//! The actor loop.
//!
//! One `select` over five sources: inbound frames from the socket, the request
//! channel, the close channel, the timer that expires timeouts and deadlines,
//! and the socket write currently in progress. Every arrival on the first four
//! is a transition in the request table and nothing else, which is what keeps
//! the request states from being reimplemented per call site.
//!
//! **A blocked socket write never stops the actor reading replies or firing
//! timers.** A peer whose receive window has closed can block a write
//! indefinitely; an actor that ran the write to completion inside its dispatch
//! branch would stop reading inbound frames while blocked, the server's send
//! buffer would fill, the server would stop reading requests, and the write
//! would never complete — with the timer in the same `select`, nothing would
//! break the deadlock. So the write in progress is a source of the `select` in
//! its own right.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::sync::{mpsc, oneshot};
use tokio::time::{Instant, sleep_until};
use tracing::{debug, trace, warn};

use crate::status::NtStatus;
use crate::wire::andx;
use crate::wire::header::{SmbHeader, command};
use crate::wire::netbios::{self, MessageType};
use crate::wire::{self, Message};

use super::reassembly::Assembly;
use super::table::RequestTable;
use super::{Connection, Dispatch, Error, Negotiated, Reply, Timeouts};

/// How many closes may reach the wire in a row while a request waits behind
/// them.
///
/// The close queue is bounded in memory but would otherwise be unbounded in its
/// share of capacity: a task dropping handles in a loop keeps it non-empty, and
/// draining it first without limit would hold every other task's requests off
/// the wire indefinitely.
const CLOSE_RUN: usize = 8;

/// The commands whose response carries an AndX prologue, and so can claim to
/// chain another.
const ANDX_RESPONSES: [u8; 6] = [
    command::READ_ANDX,
    command::WRITE_ANDX,
    command::SESSION_SETUP_ANDX,
    command::LOGOFF_ANDX,
    command::TREE_CONNECT_ANDX,
    command::NT_CREATE_ANDX,
];

/// What the socket delivered.
enum Inbound {
    /// One SMB message.
    Message(Message),
    /// A NetBIOS keep-alive, which is transport-level and carries nothing.
    KeepAlive,
}

/// Which part of a frame is being read.
#[derive(Debug, Clone, Copy)]
enum Reading {
    Header,
    Body,
    KeepAlive,
}

/// An incremental frame reader.
///
/// It is a state machine rather than a `read_exact` because it is polled from a
/// `select`: the accumulated bytes live here, and one step is a single `read`
/// into the space still owed, which is cancel-safe — a step the `select`
/// abandons has read nothing.
struct FrameReader {
    /// Sized to exactly what is being read, so a read can never run past the
    /// end of the frame in hand and confuse the next frame's boundary.
    buffer: Vec<u8>,
    filled: usize,
    state: Reading,
}

impl FrameReader {
    fn new() -> Self {
        Self {
            buffer: vec![0; netbios::HEADER_LEN],
            filled: 0,
            state: Reading::Header,
        }
    }

    fn expect_header(&mut self) {
        self.buffer = vec![0; netbios::HEADER_LEN];
        self.filled = 0;
        self.state = Reading::Header;
    }

    /// Advances the state machine over a buffer that has just filled.
    fn take(&mut self) -> Result<Option<Inbound>, Error> {
        match self.state {
            Reading::Header => {
                let header: [u8; netbios::HEADER_LEN] = self.buffer[..]
                    .try_into()
                    .expect("the header buffer is four bytes");
                let (kind, length) = netbios::decode_header(header)?;
                self.state = match kind {
                    MessageType::SessionMessage => Reading::Body,
                    MessageType::KeepAlive => Reading::KeepAlive,
                };
                self.buffer = vec![0; length];
                self.filled = 0;
                Ok(None)
            }
            Reading::Body => {
                let message = Message::parse(std::mem::take(&mut self.buffer))?;
                self.expect_header();
                Ok(Some(Inbound::Message(message)))
            }
            Reading::KeepAlive => {
                self.expect_header();
                Ok(Some(Inbound::KeepAlive))
            }
        }
    }

    /// One poll's worth of reading.
    async fn step<R: AsyncRead + Unpin>(
        &mut self,
        reader: &mut R,
    ) -> Result<Option<Inbound>, Error> {
        if self.filled < self.buffer.len() {
            let read = reader.read(&mut self.buffer[self.filled..]).await?;
            if read == 0 {
                return Err(Error::Io(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "the server closed the connection",
                )));
            }
            self.filled += read;
        }
        loop {
            if self.filled < self.buffer.len() {
                return Ok(None);
            }
            if let Some(inbound) = self.take()? {
                return Ok(Some(inbound));
            }
        }
    }
}

/// What enters the request table at the first byte on the socket.
struct Queued {
    mid: u16,
    command: u8,
    reply: Option<oneshot::Sender<Result<Reply, Error>>>,
    assembly: Option<Assembly>,
}

/// The frame the actor is putting on the socket.
struct Writing {
    frame: Vec<u8>,
    cursor: usize,
    /// Taken at the first byte written, which is where dispatch commits.
    queued: Option<Queued>,
}

impl Writing {
    fn remaining(&self) -> &[u8] {
        &self.frame[self.cursor..]
    }
}

/// Which source of the `select` produced something.
enum Event {
    Close(Option<Dispatch>),
    Request(Option<Dispatch>),
    Inbound(Result<Option<Inbound>, Error>),
    Written(io::Result<usize>),
    Timer,
}

/// The connection task.
pub(crate) struct Actor<S> {
    reader: ReadHalf<S>,
    writer: WriteHalf<S>,
    inbound: FrameReader,
    writing: Option<Writing>,
    requests: mpsc::Receiver<Dispatch>,
    closes: mpsc::UnboundedReceiver<Dispatch>,
    requests_done: bool,
    closes_done: bool,
    table: RequestTable,
    timeouts: Timeouts,
    /// Where the current stretch of silence starts: the later of the last
    /// message to arrive and the moment a caller started waiting on an
    /// otherwise-idle connection.
    ///
    /// The window the silence rule measures is silence *a caller spends
    /// waiting*, so idle time cannot accumulate into it. Measuring from the
    /// last message alone would fail a connection on the first request after a
    /// long idle stretch — including the cache's own liveness probe, which
    /// exists to answer exactly that connection.
    silence_since: Instant,
    consecutive_closes: usize,
}

/// Puts a connection actor on an already-negotiated, already-authenticated
/// stream.
pub(crate) fn spawn<S>(stream: S, negotiated: Negotiated, timeouts: Timeouts) -> Connection
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    let limit = negotiated.admission_limit();
    // The channel's bound is the admission limit itself, derived from it rather
    // than configured beside it, so the two cannot be tuned into contradiction.
    let (requests, requests_rx) = mpsc::channel(limit);
    let (closes, closes_rx) = mpsc::unbounded_channel();
    let (reader, writer) = tokio::io::split(stream);

    let actor = Actor {
        reader,
        writer,
        inbound: FrameReader::new(),
        writing: None,
        requests: requests_rx,
        closes: closes_rx,
        requests_done: false,
        closes_done: false,
        table: RequestTable::new(limit, timeouts),
        timeouts,
        silence_since: Instant::now(),
        consecutive_closes: 0,
    };
    tokio::spawn(actor.run());

    Connection {
        requests,
        closes,
        negotiated,
    }
}

impl<S> Actor<S>
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    async fn run(mut self) {
        match self.pump().await {
            Ok(()) => debug!("connection closed; every handle on it has gone"),
            Err(error) => warn!("connection failed: {error}"),
        }
        // A connection being torn down because it failed says no goodbye: there
        // is nothing left to send it over, and TCP teardown releases everything
        // the server holds anyway.
        self.table.fail_all();
    }

    async fn pump(&mut self) -> Result<(), Error> {
        loop {
            // The run of eight bounds closes against a request that is actually
            // waiting. With either queue empty there is nothing to starve.
            if self.requests.is_empty() || self.closes.is_empty() {
                self.consecutive_closes = 0;
            }
            if self.requests_done
                && self.closes_done
                && self.writing.is_none()
                && self.table.charging() == 0
            {
                return Ok(());
            }

            // Admission is one act: a request leaves Queued only while
            // |Live| + |Orphaned| is below the limit, and Queued holds at most
            // one request. While the limit is reached the actor stops draining
            // the request channel at all, which is where the backpressure lives.
            let can_admit = self.writing.is_none() && self.table.charging() < self.table.limit();
            let take_close = can_admit && !self.closes_done && self.consecutive_closes < CLOSE_RUN;
            let take_request = can_admit
                && !self.requests_done
                && (self.consecutive_closes >= CLOSE_RUN || self.closes.is_empty());
            let wake = self.next_wake();

            // Every branch yields a value that borrows nothing, so the sources
            // stay disjoint and the handling below has the actor to itself.
            let event = tokio::select! {
                dispatch = self.closes.recv(), if take_close => Event::Close(dispatch),
                dispatch = self.requests.recv(), if take_request => Event::Request(dispatch),
                inbound = self.inbound.step(&mut self.reader) => Event::Inbound(inbound),
                // `select!` builds every branch's future before it decides
                // which to poll, so this expression has to be safe with no
                // write in progress; the precondition is what stops it being
                // polled.
                written = self.writer.write(
                    self.writing.as_ref().map_or(&[][..], Writing::remaining),
                ), if self.writing.is_some() => Event::Written(written),
                () = sleep_until(wake.unwrap_or_else(Instant::now)), if wake.is_some() => Event::Timer,
            };

            match event {
                Event::Close(None) => self.closes_done = true,
                Event::Close(Some(dispatch)) => {
                    self.consecutive_closes += 1;
                    self.begin(dispatch)?;
                }
                Event::Request(None) => self.requests_done = true,
                Event::Request(Some(dispatch)) => {
                    self.consecutive_closes = 0;
                    self.begin(dispatch)?;
                }
                Event::Inbound(inbound) => {
                    if let Some(inbound) = inbound? {
                        self.route(inbound)?;
                    }
                }
                Event::Written(written) => self.wrote(written?)?,
                Event::Timer => self.tick()?,
            }
        }
    }

    /// Takes one request from a channel and starts putting it on the socket.
    fn begin(&mut self, dispatch: Dispatch) -> Result<(), Error> {
        let Dispatch { request, reply } = dispatch;

        // Queued, and the caller has gone: the request is Done without reaching
        // the wire. Nothing is withdrawn, because nothing was sent.
        if let Some(reply) = &reply
            && reply.is_closed()
        {
            debug!(
                "caller dropped before dispatch; command {:#04x} is not sent",
                request.command
            );
            return Ok(());
        }

        let mid = self.table.allocate().ok_or(Error::PoolExhausted)?;
        let header = SmbHeader {
            mid,
            tid: request.tid,
            uid: request.uid,
            ..SmbHeader::request(request.command)
        };
        let frame =
            match wire::message(&header, &request.body).and_then(|whole| wire::frame(&whole)) {
                Ok(frame) => frame,
                Err(error) => {
                    // Nothing reached the socket, so the multiplex id was never
                    // used and the failure is this request's alone.
                    if let Some(reply) = reply {
                        let _ = reply.send(Err(error.into()));
                    }
                    return Ok(());
                }
            };

        let assembly = request
            .transaction
            .then(|| Assembly::new(request.max_parameter_count, request.max_data_count));
        self.writing = Some(Writing {
            frame,
            cursor: 0,
            queued: Some(Queued {
                mid,
                command: request.command,
                reply,
                assembly,
            }),
        });
        Ok(())
    }

    /// Takes what the socket accepted of the frame in progress.
    fn wrote(&mut self, written: usize) -> Result<(), Error> {
        if written == 0 {
            return Err(Error::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                "the socket accepted no bytes of a request",
            )));
        }
        let writing = self
            .writing
            .as_mut()
            .expect("a write reported progress without one in progress");
        if let Some(queued) = writing.queued.take() {
            // Dispatch commits at the first byte written: from here the request
            // is on the wire, the actor finishes the frame whatever the caller
            // does or the clock says, and the per-request clock starts.
            if self.table.charging() == 0 {
                // A caller starts waiting on a connection nothing was being
                // asked of, which is where this stretch of silence begins.
                self.silence_since = Instant::now();
            }
            self.table.dispatch(
                queued.mid,
                queued.command,
                queued.reply,
                queued.assembly,
                Instant::now(),
            );
        }
        let writing = self
            .writing
            .as_mut()
            .expect("a write reported progress without one in progress");
        writing.cursor += written;
        let done = writing.cursor >= writing.frame.len();
        if done {
            self.writing = None;
        }
        Ok(())
    }

    /// Gives one inbound frame its outcome.
    fn route(&mut self, inbound: Inbound) -> Result<(), Error> {
        let message = match inbound {
            // Transport-level, carrying nothing: the one exception to nothing
            // being discarded. It is not an answer either, so it does not reset
            // the silence window — admitting it would let a server hold a
            // connection open indefinitely by keeping the socket warm and doing
            // nothing else.
            Inbound::KeepAlive => {
                trace!("NetBIOS keep-alive; consumed and discarded");
                return Ok(());
            }
            Inbound::Message(message) => message,
        };

        if let Some(next) = chained_command(&message) {
            return Err(Error::ChainedResponse(next));
        }

        let status = message.header().status;
        self.silence_since = Instant::now();
        self.table.accept(message, self.silence_since)?;

        if status == NtStatus::USER_SESSION_DELETED {
            // Session-scoped, and a connection carries exactly one session, so
            // session and connection are the same object here. The reply
            // reaches its caller first, which is why this is checked after
            // routing rather than before it.
            return Err(Error::SessionDeleted);
        }
        Ok(())
    }

    /// Fires whatever the clock has reached.
    fn tick(&mut self) -> Result<(), Error> {
        let now = Instant::now();
        // A connection fails when no message of any kind has arrived for one
        // overall deadline while at least one request is still charging
        // capacity. A lapsed request does not hold the window open: nobody is
        // waiting on it, and letting it keep the window running would fail a
        // connection nothing was being asked of.
        if self.table.charging() > 0
            && now.saturating_duration_since(self.silence_since) >= self.timeouts.overall
        {
            return Err(Error::Silent);
        }
        self.table.expire(now)
    }

    fn next_wake(&self) -> Option<Instant> {
        let silence =
            (self.table.charging() > 0).then(|| self.silence_since + self.timeouts.overall);
        match (self.table.next_expiry(), silence) {
            (Some(expiry), Some(silence)) => Some(expiry.min(silence)),
            (expiry, silence) => expiry.or(silence),
        }
    }
}

/// The command a response claims to chain, if it claims one.
///
/// This crate chains nothing, so a chained response is the server answering
/// something that was not asked, and parsing on into the chain is how a decoder
/// loses frame boundaries.
fn chained_command(message: &Message) -> Option<u8> {
    if !ANDX_RESPONSES.contains(&message.header().command) {
        return None;
    }
    match message.words().first().copied() {
        Some(next) if next != andx::NO_FURTHER_COMMAND => Some(next),
        _ => None,
    }
}
