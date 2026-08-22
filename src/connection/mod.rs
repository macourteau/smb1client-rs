//! The connection actor: one task owning the socket and the table of requests.
//!
//! SMB1 is multiplexed — requests carry a 16-bit multiplex id and responses
//! return out of order — so something must read frames continuously and route
//! each to whichever caller is waiting on that id. Here that is one tokio task
//! which owns the stream and the request table outright. Nothing about the
//! connection is shared, so there is no mutex anywhere in the transport;
//! callers hold a cheap [`Connection`] handle that sends the task a request
//! together with somewhere to put the reply, and await the answer.
//!
//! Three properties this layer holds, and which nothing above it has to
//! re-establish:
//!
//! 1. **A caller never observes a partial transaction.** A reply spread across
//!    several messages is delivered once every byte of the declared parameter
//!    and data ranges has been *covered* — coverage tracked across each range,
//!    never a running sum of byte counts.
//! 2. **No response is discarded silently.** Every frame reaches its request,
//!    or reaches a multiplex id the connection has retired and is logged
//!    against that identity, or fails the connection. A NetBIOS keep-alive is
//!    the one exception: it is transport-level and carries nothing.
//! 3. **The requests this client charges capacity for never exceed the
//!    connection's admission limit**, however many tasks a consumer runs.
//!
//! The handshake completes before the actor takes ownership of the stream, so
//! the negotiated parameters reach it as values it is constructed with rather
//! than as state it must observe. That is what makes them injectable, and it is
//! why [`transport::spawn`] is public surface rather than test scaffolding.

mod actor;
mod reassembly;
mod table;
pub mod transport;

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tokio::sync::{mpsc, oneshot};

use crate::status::NtStatus;
use crate::wire::{Message, WireError};

pub(crate) use reassembly::Coverage;
pub use reassembly::ReassemblyError;

/// The default per-request timeout: the span of silence after which a request
/// stops charging capacity.
pub const DEFAULT_PER_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The default overall deadline, which bounds one request's whole life however
/// much progress it makes.
pub const DEFAULT_OVERALL_DEADLINE: Duration = Duration::from_secs(300);

/// The ceiling on the admission limit, whatever the server negotiates.
///
/// Its job is to bound reassembly memory: a request holding a reassembly buffer
/// is a request charging capacity.
pub const ADMISSION_CEILING: usize = 50;

/// `CAP_LARGE_READX`, which lifts a read chunk off the negotiated buffer.
pub const CAP_LARGE_READX: u32 = 0x0000_4000;

/// `CAP_LARGE_WRITEX`, the write half of the same.
pub const CAP_LARGE_WRITEX: u32 = 0x0000_8000;

/// The chunk size a large-I/O capability buys: the NetBIOS frame limit less the
/// reservation a message's own headers take.
///
/// Carried from the reference's `MaxDataSize` with the reservation already
/// taken, rather than recomputed from the 131,071-byte inbound ceiling.
pub const LARGE_IO_CHUNK: usize = 130_048;

/// What a chunk asks for where the capability is absent.
///
/// It comes from the field that asks for the bytes rather than from the
/// negotiated buffer: `MaxCountOfBytesToReturn` is 16 bits without the
/// capability.
pub const SMALL_IO_CHUNK: usize = 65_520;

/// What a message's own headers take out of the buffer before any payload does.
///
/// Asking for exactly `MaxBufferSize` overruns it by however much of it they
/// take. Neither subtraction below is guarded, and neither needs to be: a
/// `MaxBufferSize` under the 4,356-byte SMB1 minimum failed the connection when
/// the negotiate response arrived.
pub const PROTOCOL_OVERHEAD: u32 = 1_024;

/// The two timing bounds the connection works to.
///
/// The connect timeout is not among them: it bounds the dial and the handshake,
/// both of which are complete before the actor takes the stream.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Timeouts {
    /// How long a request may go without *any* message reaching it before it
    /// stops charging capacity. It measures silence rather than elapsed work:
    /// every message that reaches a request still charging capacity resets it,
    /// and it starts at dispatch — at the first byte on the socket — so time
    /// spent waiting for capacity does not consume it.
    pub per_request: Duration,
    /// The bound on one request's whole life, which caps how far its own
    /// progress may extend the per-request timeout.
    ///
    /// It does four further jobs here and in the layers above: it is the span
    /// of silence that fails a connection, and at eight times its value it is
    /// how long a lapsed request waits before it is given up on and its
    /// multiplex id retired. The cache adds the other two.
    pub overall: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            per_request: DEFAULT_PER_REQUEST_TIMEOUT,
            overall: DEFAULT_OVERALL_DEADLINE,
        }
    }
}

/// What the handshake negotiated, handed to the actor as values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Negotiated {
    /// The most requests the server said it will work on at once.
    pub max_mpx_count: u16,
    /// The largest single SMB message the server will accept.
    pub max_buffer_size: u32,
    /// The server's capability word.
    pub capabilities: u32,
}

impl Negotiated {
    /// The connection's admission limit: `min(MaxMpxCount, 50)`.
    ///
    /// A server reporting 0 or 1 is saying under \[MS-CIFS\] that it does not
    /// multiplex, so its limit is 1 and the connection is serial. This is the
    /// number the client also advertises in its own session setup, so what the
    /// server is told to expect is exactly what the client enforces.
    pub fn admission_limit(&self) -> usize {
        match self.max_mpx_count {
            0 | 1 => 1,
            count => usize::from(count).min(ADMISSION_CEILING),
        }
    }
}

/// One request for the connection to issue.
///
/// The body is a command body as the wire layer encodes it — the `WordCount`,
/// the word block, the `ByteCount` and the byte area. The header is the
/// connection's to build: it assigns the multiplex id at dispatch, and nothing
/// above it may.
#[derive(Debug, Clone)]
pub struct Request {
    command: u8,
    tid: u16,
    uid: u16,
    body: Vec<u8>,
    max_parameter_count: u16,
    max_data_count: u16,
    outcome: Option<Arc<dyn RequestOutcome>>,
}

/// What a caller arranged to outlive a request it may stop waiting for.
///
/// Dropping a future withdraws nothing from the wire, so a request whose caller
/// has gone still reaches a terminal outcome — its reply, its own lapse, or the
/// connection ending it — and something has to be able to observe that after
/// the caller is no longer there to. The actor applies this hook exactly once,
/// whichever way the request ends and whether or not anybody was still waiting,
/// so the two paths cannot record different things.
///
/// A late reply to a request that has already lapsed applies nothing: the hook
/// was applied at the lapse, which is the terminal outcome as far as the caller
/// is concerned.
pub(crate) trait RequestOutcome: fmt::Debug + Send + Sync {
    /// The request ended.
    fn ended(&self, outcome: Result<&Reply, &Error>);
}

impl Request {
    /// A request whose reply arrives in one message.
    ///
    /// Whether a reply is reassembled is decided by the command and not by
    /// which constructor built the request, so a transaction built here is
    /// still reassembled — against a bound of nothing, which the first reply
    /// carrying any bytes fails as [`ReassemblyError::MoreThanAsked`]. Use
    /// [`Request::transaction`] for those.
    pub fn new(command: u8, tid: u16, uid: u16, body: Vec<u8>) -> Self {
        Self {
            command,
            tid,
            uid,
            body,
            max_parameter_count: 0,
            max_data_count: 0,
            outcome: None,
        }
    }

    /// A TRANS2 or `SMB_COM_TRANSACTION` request, whose reply may arrive across
    /// several messages.
    ///
    /// The two counts are the request's own `MaxParameterCount` and
    /// `MaxDataCount`. They are what bounds the reassembly buffer: the totals a
    /// reply declares are server-supplied numbers, so sizing from them would
    /// hand the server the allocation decision, and a reply exceeding what it
    /// was asked for fails as a nameable protocol error instead.
    pub fn transaction(
        command: u8,
        tid: u16,
        uid: u16,
        body: Vec<u8>,
        max_parameter_count: u16,
        max_data_count: u16,
    ) -> Self {
        Self {
            command,
            tid,
            uid,
            body,
            max_parameter_count,
            max_data_count,
            outcome: None,
        }
    }

    /// The command this request carries.
    pub fn command(&self) -> u8 {
        self.command
    }

    /// Arranges for `outcome` to be applied when this request ends, whether or
    /// not its caller is still waiting by then.
    pub(crate) fn outliving(mut self, outcome: Arc<dyn RequestOutcome>) -> Self {
        self.outcome = Some(outcome);
        self
    }
}

/// The parameter and data blocks of a reassembled transaction reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionBody {
    setup: Vec<u16>,
    parameters: Vec<u8>,
    data: Vec<u8>,
}

impl TransactionBody {
    /// The reply's setup words, of which the replies this crate asks for carry
    /// none.
    pub fn setup(&self) -> &[u16] {
        &self.setup
    }

    /// The whole reply's parameter block.
    pub fn parameters(&self) -> &[u8] {
        &self.parameters
    }

    /// The whole reply's data block.
    pub fn data(&self) -> &[u8] {
        &self.data
    }
}

/// A completed reply.
///
/// The unit of routing is a completed transaction and not a frame, so there is
/// exactly one of these per request. Where the reply was a transaction that
/// carried a body, [`Reply::transaction`] holds it reassembled; for every other
/// command the reply is the one message, and the decoders that read it work off
/// [`Reply::message`].
#[derive(Debug, Clone)]
pub struct Reply {
    message: Message,
    transaction: Option<TransactionBody>,
}

impl Reply {
    /// The status the reply's header carries.
    pub fn status(&self) -> NtStatus {
        self.message.header().status
    }

    /// The command the reply answers.
    pub fn command(&self) -> u8 {
        self.message.header().command
    }

    /// The tree id the reply's header carries.
    pub fn tid(&self) -> u16 {
        self.message.header().tid
    }

    /// The user id the reply's header carries.
    pub fn uid(&self) -> u16 {
        self.message.header().uid
    }

    /// The whole SMB message that completed the reply, its NetBIOS header
    /// stripped. Absolute offsets inside a message are measured against this.
    pub fn message(&self) -> &[u8] {
        self.message.as_bytes()
    }

    /// The parsed message, for the per-command decoders.
    ///
    /// They read it rather than re-parsing [`Reply::message`], which costs
    /// little on a share list and a great deal on a 64 KB read.
    pub(crate) fn parsed(&self) -> &Message {
        &self.message
    }

    /// The reassembled transaction blocks, where the reply carried any.
    pub fn transaction(&self) -> Option<&TransactionBody> {
        self.transaction.as_ref()
    }
}

/// What can go wrong on a connection.
///
/// The variants divide into two groups that are worth telling apart, and the
/// division is stated here rather than encoded in the type: [`Error::Timeout`],
/// [`Error::Reassembly`] and [`Error::Wire`] fail one request and leave the
/// connection working, while everything else means the connection is gone and
/// the next call must re-dial.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The socket failed.
    #[error("connection I/O failed: {0}")]
    Io(#[from] std::io::Error),

    /// A message could not be encoded or decoded.
    #[error(transparent)]
    Wire(#[from] WireError),

    /// The request stopped charging capacity without its reply arriving: either
    /// the per-request timeout expired with nothing reaching it, or the overall
    /// deadline capped the resets its own progress was buying.
    ///
    /// It is not proof the server finished. The request keeps its multiplex id
    /// until its reply arrives whole or it is given up on.
    #[error("request timed out with no reply")]
    Timeout,

    /// The server corrupted the reply's reassembly. This fails the request and
    /// retires its multiplex id; the connection carries on.
    #[error("reply reassembly failed: {0}")]
    Reassembly(#[from] ReassemblyError),

    /// The connection had already died. The next call through the cache
    /// re-dials; this one cannot be retried, because writes are not idempotent.
    #[error("connection lost")]
    Lost,

    /// A frame arrived on a multiplex id no request holds and the table does
    /// not remember as retired, or on one whose command does not match the
    /// request's. Carrying on past it risks misrouting the next frame.
    #[error("frame on multiplex id {mid} for command {command:#04x} routes to no request")]
    Unroutable {
        /// The multiplex id the frame carried.
        mid: u16,
        /// The command the frame carried.
        command: u8,
    },

    /// A response chained another command. This crate chains nothing, so a
    /// chained response is the server answering something that was not asked,
    /// and parsing on into the chain is how a decoder loses frame boundaries.
    #[error("response chains command {0:#04x}")]
    ChainedResponse(u8),

    /// The server discarded the session. A connection carries exactly one
    /// session, so session and connection are the same object here.
    #[error("server reports the session was deleted")]
    SessionDeleted,

    /// Nothing arrived for one overall deadline while a request was still
    /// waiting. A silent drop with no FIN leaves the actor reading a socket
    /// that will never speak again, and every later call would spend a full
    /// timeout on it.
    #[error("no message arrived for one overall deadline with requests outstanding")]
    Silent,

    /// Too many multiplex ids have been retired. A server that accepts requests
    /// and never finishes them is one this client should stop talking to.
    #[error("{0} multiplex ids retired; the connection is not making progress")]
    RetirementBudget(usize),

    /// Every multiplex id is held at once.
    #[error("the multiplex id pool is exhausted")]
    PoolExhausted,
}

/// What the handle sends the actor.
#[derive(Debug)]
struct Dispatch {
    request: Request,
    /// Where the reply goes. `None` is a close the caller's `Drop` enqueued,
    /// which has nobody to return to and is dispatched already orphaned.
    reply: Option<oneshot::Sender<Result<Reply, Error>>>,
}

/// A handle on a connection.
///
/// Cheap to clone and usable from as many tasks as a consumer likes: what
/// limits how much can be in flight is the connection's admission limit, and it
/// reaches the caller as backpressure on [`Connection::request`] rather than as
/// a lock.
#[derive(Debug, Clone)]
pub struct Connection {
    requests: mpsc::Sender<Dispatch>,
    /// `Drop`'s closes travel on their own unbounded channel. `Drop` cannot
    /// await, so a bounded channel would force a fallible non-blocking send
    /// that discards when full — the silent-loss shape invariant 2 forbids.
    closes: mpsc::UnboundedSender<Dispatch>,
    negotiated: Negotiated,
    /// Whether this connection has been recorded small-buffer, which a server
    /// refusing a large read or write does for the connection's whole life.
    /// Shared, because the record belongs to the connection and not to whichever
    /// handle met the refusal.
    downgraded: Arc<AtomicBool>,
}

impl Connection {
    /// What the handshake negotiated.
    pub fn negotiated(&self) -> Negotiated {
        self.negotiated
    }

    /// The largest payload one `READ_ANDX` on this connection asks for.
    pub fn read_chunk_size(&self) -> usize {
        self.chunk_size(CAP_LARGE_READX)
    }

    /// The largest payload one `WRITE_ANDX` on this connection carries.
    pub fn write_chunk_size(&self) -> usize {
        self.chunk_size(CAP_LARGE_WRITEX)
    }

    /// The three cases the chunk size has.
    ///
    /// With the large-I/O capability the bound is the NetBIOS frame rather than
    /// the negotiated buffer — a 130,108-byte read reply against a 16,644-byte
    /// negotiated buffer is what says so. Without it the bound is the 16-bit
    /// field that asks for the bytes, under the reservation. After the one-shot
    /// downgrade it is the negotiated buffer under that same reservation, which
    /// is the only case that changes what a capability-bearing server is asked
    /// for.
    fn chunk_size(&self, capability: u32) -> usize {
        let buffered = self
            .negotiated
            .max_buffer_size
            .saturating_sub(PROTOCOL_OVERHEAD) as usize;
        if self.downgraded.load(Ordering::Relaxed) {
            return buffered;
        }
        if self.negotiated.capabilities & capability != 0 {
            LARGE_IO_CHUNK
        } else {
            buffered.min(SMALL_IO_CHUNK)
        }
    }

    /// Whether the chunk size a request is about to be issued at is already the
    /// downgraded one. A chunk issued at the small size has no second attempt
    /// to make.
    pub(crate) fn is_downgraded(&self) -> bool {
        self.downgraded.load(Ordering::Relaxed)
    }

    /// Records the connection small-buffer, which a server refusing a large
    /// read or write does once and for the connection's whole life.
    pub(crate) fn record_small_buffer(&self) {
        if !self.downgraded.swap(true, Ordering::Relaxed) {
            tracing::warn!(
                "the server refused a large read or write; every later chunk on this connection \
                 is bounded by MaxBufferSize less the protocol overhead"
            );
        }
    }

    /// Issues one request and waits for its reply.
    ///
    /// The wait is bounded by the per-request timeout and the overall deadline.
    /// Dropping this future withdraws nothing from the wire — SMB1 offers no
    /// way to cancel — so the request goes on charging capacity until its reply
    /// arrives or it lapses.
    ///
    /// Where the connection is at its admission limit this waits for capacity,
    /// and that wait does not consume the per-request timeout, which starts at
    /// the first byte on the socket.
    pub async fn request(&self, request: Request) -> Result<Reply, Error> {
        let (reply, answer) = oneshot::channel();
        self.requests
            .send(Dispatch {
                request,
                reply: Some(reply),
            })
            .await
            .map_err(|_| Error::Lost)?;
        answer.await.map_err(|_| Error::Lost)?
    }

    /// Enqueues a best-effort close for a handle that has been dropped.
    ///
    /// It neither awaits nor spawns anything, which is what lets `Drop` call
    /// it. The close is queued ahead of whatever the caller does next on this
    /// connection: the actor takes a waiting close before a waiting request.
    /// That settles send order and nothing more — an operation that needs the
    /// server to have finished the close must await the close's reply instead.
    pub fn enqueue_close(&self, request: Request) {
        // A send that fails means the actor is gone, and a close only matters
        // while the connection lives: the server releases every handle on TCP
        // disconnect.
        if self
            .closes
            .send(Dispatch {
                request,
                reply: None,
            })
            .is_err()
        {
            tracing::debug!("connection already closed; the queued close is abandoned");
        }
    }
}
