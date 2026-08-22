//! `File`, and the two chunk loops underneath every read and write in the
//! crate.
//!
//! **`read_exact_at` returns `Result<()>` and a span it cannot fill is an
//! error.** The contract is std's, the one the name carries. The signature
//! carries no count, so end of file is not an outcome a caller reads off a
//! return value: it is the error a request for bytes the file does not hold
//! produces. A short return the caller must notice is the same silent-truncation
//! hazard relocated from library code into every consumer's read loop.
//!
//! **The fill loop tracks which ranges of the requested span have arrived**, the
//! same coverage rule reassembly uses and for the same reason: the loop
//! pipelines, so replies land out of order and a short one in the middle is not
//! the end of anything. Three rules govern it, and they are one rule seen from
//! three sides:
//!
//! - a chunk answered short is re-issued for the bytes it did not return, which
//!   is how the span comes to be covered — and against Windows that path runs on
//!   *every* large read, since it serves every `READ_ANDX` `min(asked, 65536)`
//!   while accepting a 130,048-byte write;
//! - a chunk answered with zero bytes is never re-issued — the loop's
//!   no-progress guard, read off those same ranges rather than off the cached
//!   size, which nothing may gate a read on. `STATUS_END_OF_FILE` is that same
//!   answer under a status rather than a count;
//! - once every issued chunk has been answered, any range of the span still
//!   uncovered fails the call, a hole in the middle and a short far end alike.
//!
//! The write carries the symmetric rule, because short writes happen: the
//! remainder of a short-acknowledged chunk is re-issued from the first
//! unacknowledged byte, and a chunk acknowledged with zero bytes is an error
//! rather than another attempt.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::Poll;

use tracing::debug;

use crate::connection::{Coverage, Reply, Request};
use crate::error::{Error, Result};
use crate::status::NtStatus;
use crate::tree::{self, TreeInner};
use crate::wire::file as wire_file;
use crate::wire::header::command;
use crate::wire::info;
use crate::wire::io::{ReadAndxRequest, ReadAndxResponse, WriteAndxRequest, WriteAndxResponse};
use crate::wire::transaction::TransactionRequest;

use super::adapter::{FileReader, FileWriter};
use super::progress::WriteProgress;

/// How deep one operation pipelines.
///
/// The admission limit bounds what the whole connection carries; this bounds one
/// call's share of it, so a single `read_exact_at` over a large buffer cannot
/// take a connection's entire capacity, or hold the admission limit's worth of
/// 130 KB reply frames, while every other task on it waits. It is chosen rather
/// than measured.
pub const PIPELINE_DEPTH: usize = 4;

/// The buffer size above which a one-shot read pipelines at all. Inherited from
/// the reference, which has no recorded rationale for it and no test pinning it.
pub const READ_PIPELINE_THRESHOLD: usize = 128 * 1024;

/// The same for a one-shot write. Inherited on the same terms.
pub const WRITE_PIPELINE_THRESHOLD: usize = 256 * 1024;

/// `WriteMode` on every write this crate sends.
///
/// It asks for no write-through, so an acknowledgement says the server accepted
/// the bytes and not that they reached its disk — which is what makes an
/// acknowledged prefix the right thing to resume from and the wrong thing to
/// call durable.
const WRITE_MODE: u16 = 0;

/// The three statuses that mean a server refused a large read or write, and the
/// only ones that downgrade anything.
///
/// A trigger left as "any error" would spend a connection's throughput on an
/// unrelated failure. The third is ambiguous by this design's own admission —
/// excess multiplexing earns the same status — so a lapse can cost a connection
/// its chunk size for the rest of that connection's life. That is accepted in
/// the direction it errs, which is working slowly rather than failing at all.
fn refuses_the_size(status: NtStatus) -> bool {
    status == NtStatus::INVALID_SMB
        || status == NtStatus::INVALID_PARAMETER
        || status == NtStatus::INSUFF_SERVER_RESOURCES
}

/// What an open file is, shared by the handle a caller holds and by the adapters
/// built on it.
///
/// It is separate from [`File`] because the adapters own futures that outlive
/// any borrow, so what they carry has to be cheap to clone and free of the
/// close-on-drop responsibility, which stays with the `File`.
#[derive(Debug, Clone)]
pub(crate) struct Handle {
    pub(crate) tree: Arc<TreeInner>,
    pub(crate) fid: u16,
}

/// How a fill ended.
#[derive(Debug)]
pub(crate) struct Fill {
    /// Which ranges of the span arrived.
    pub(crate) covered: Coverage,
    /// Whether the far end was reached: a chunk answered with zero bytes, or
    /// `STATUS_END_OF_FILE`. **Read off the wire and not off a cached size**,
    /// which nothing may gate a read on.
    pub(crate) at_end: bool,
}

impl Handle {
    /// Fills `buffer` from `offset`, pipelining `depth` chunks deep.
    pub(crate) async fn read_span(
        &self,
        buffer: &mut [u8],
        offset: u64,
        depth: usize,
    ) -> Result<Fill> {
        let mut covered = Coverage::default();
        let mut at_end = false;
        if buffer.is_empty() {
            return Ok(Fill { covered, at_end });
        }

        let mut issued: Vec<Chunk<'_>> = Vec::new();
        // Spans that still have to be asked for: the unread tail, and whatever a
        // short answer left behind.
        let mut queue: Vec<(usize, usize)> = Vec::new();
        let mut next = 0usize;

        loop {
            while issued.len() < depth {
                let chunk_size = self.tree.connection().read_chunk_size().max(1);
                // A re-queued span is re-clamped, and that is the whole of what
                // makes the one-shot downgrade work. A span lands back on this
                // queue because the server refused its size; handing it back
                // unchanged would ask again at exactly the size just refused,
                // and the retry would fail for the reason the first attempt did.
                // Anything left over goes back for the round after.
                let span = queue
                    .pop()
                    .map(|(start, length)| {
                        let take = chunk_size.min(length);
                        if take < length {
                            queue.push((start + take, length - take));
                        }
                        (start, take)
                    })
                    .or_else(|| {
                        (!at_end && next < buffer.len()).then(|| {
                            let length = chunk_size.min(buffer.len() - next);
                            let span = (next, length);
                            next += length;
                            span
                        })
                    });
                let Some((start, length)) = span else { break };
                issued.push(self.read_chunk(offset + start as u64, start, length));
            }
            if issued.is_empty() {
                break;
            }

            let (chunk, answer) = first_answered(&mut issued).await;
            let reply = answer?;

            if refuses_the_size(reply.status()) {
                self.tree.connection().record_small_buffer();
                if chunk.large {
                    // The one-shot downgrade: this operation is retried once at
                    // the smaller size, and the connection is recorded
                    // small-buffer for the rest of its life. A chunk issued
                    // after that is already bounded and has no second attempt to
                    // make, so nothing is tried a third time.
                    queue.push((chunk.start, chunk.length));
                    continue;
                }
            }
            if reply.status() == NtStatus::END_OF_FILE {
                at_end = true;
                continue;
            }
            if reply.status() != NtStatus::SUCCESS {
                return Err(self.tree.refused(reply.status()));
            }

            let data = ReadAndxResponse::decode(reply.parsed())?.data;
            let got = data.len().min(chunk.length);
            if got == 0 {
                at_end = true;
                continue;
            }
            buffer[chunk.start..chunk.start + got].copy_from_slice(&data[..got]);
            if !covered.cover(chunk.start, got) {
                return Err(Error::Protocol(Box::new(ReadError::Overlapping {
                    at: chunk.start,
                    length: got,
                })));
            }
            if got < chunk.length {
                queue.push((chunk.start + got, chunk.length - got));
            }
        }

        Ok(Fill { covered, at_end })
    }

    /// Writes `data` at `offset`, pipelining `depth` chunks deep and recording
    /// what each reply acknowledged on `progress`.
    pub(crate) async fn write_span(
        &self,
        data: &[u8],
        offset: u64,
        depth: usize,
        progress: &WriteProgress,
    ) -> Result<()> {
        if data.is_empty() {
            return Ok(());
        }
        let mut issued: Vec<Chunk<'_>> = Vec::new();
        let mut queue: Vec<(usize, usize)> = Vec::new();
        let mut next = 0usize;
        let mut failure: Option<Error> = None;

        loop {
            while failure.is_none() && issued.len() < depth {
                let chunk_size = self.tree.connection().write_chunk_size().max(1);
                // Re-clamped on the way out, for the reason the read loop gives.
                let span = queue
                    .pop()
                    .map(|(start, length)| {
                        let take = chunk_size.min(length);
                        if take < length {
                            queue.push((start + take, length - take));
                        }
                        (start, take)
                    })
                    .or_else(|| {
                        (next < data.len()).then(|| {
                            let length = chunk_size.min(data.len() - next);
                            let span = (next, length);
                            next += length;
                            span
                        })
                    });
                let Some((start, length)) = span else { break };
                let at = offset + start as u64;
                issued.push(self.write_chunk(at, start, &data[start..start + length], progress));
            }
            if issued.is_empty() {
                break;
            }

            // A failing chunk stops the loop issuing, and the loop then drains
            // what is already outstanding rather than returning the moment the
            // first error arrives: every chunk still on the wire is awaited to a
            // terminal outcome, so the prefix accounts for every request the
            // call made. The first error is the one reported; whatever the drain
            // turns up afterwards is logged.
            let (chunk, answer) = first_answered(&mut issued).await;
            let outcome = self.acknowledge(chunk, answer, &mut queue);
            match outcome {
                Ok(()) => {}
                Err(error) => match &failure {
                    None => failure = Some(error),
                    Some(_) => debug!("a later chunk of the same write also failed: {error}"),
                },
            }
        }

        match failure {
            None => Ok(()),
            Some(source) => Err(Error::WritePartial {
                written: progress.written(),
                source: Box::new(source),
            }),
        }
    }

    /// What one write reply did, and what it leaves to re-issue.
    fn acknowledge(
        &self,
        chunk: Chunk<'_>,
        answer: Result<Reply>,
        queue: &mut Vec<(usize, usize)>,
    ) -> Result<()> {
        let reply = answer?;
        if refuses_the_size(reply.status()) {
            self.tree.connection().record_small_buffer();
            if chunk.large {
                queue.push((chunk.start, chunk.length));
                return Ok(());
            }
        }
        if reply.status() != NtStatus::SUCCESS {
            return Err(self.tree.refused(reply.status()));
        }
        let acknowledged = WriteAndxResponse::decode(reply.parsed())?.count as usize;
        let acknowledged = acknowledged.min(chunk.length);
        if acknowledged == 0 {
            // The no-progress guard's write half: another attempt at a chunk the
            // server took nothing of would loop.
            return Err(Error::Protocol(Box::new(WriteError::NoProgress {
                at: chunk.start,
                length: chunk.length,
            })));
        }
        if acknowledged < chunk.length {
            queue.push((chunk.start + acknowledged, chunk.length - acknowledged));
        }
        Ok(())
    }

    fn read_chunk(&self, at: u64, start: usize, length: usize) -> Chunk<'_> {
        let large = !self.tree.connection().is_downgraded();
        let request = ReadAndxRequest {
            fid: self.fid,
            offset: at,
            max_count: length as u32,
            min_count: 0,
            remaining: 0,
        };
        Chunk {
            start,
            length,
            large,
            call: Box::pin(async move {
                self.tree
                    .request(Request::new(
                        command::READ_ANDX,
                        self.tree.tid(),
                        self.tree.uid(),
                        request.encode_body()?,
                    ))
                    .await
            }),
        }
    }

    fn write_chunk<'a>(
        &'a self,
        at: u64,
        start: usize,
        data: &[u8],
        progress: &WriteProgress,
    ) -> Chunk<'a> {
        let large = !self.tree.connection().is_downgraded();
        let length = data.len();
        let request = WriteAndxRequest {
            fid: self.fid,
            offset: at,
            write_mode: WRITE_MODE,
            remaining: 0,
            data: data.to_vec(),
        };
        // The ticket enters the chunk group here and leaves it when the request
        // ends — whichever way it ends, and whether or not this future is still
        // being awaited by then.
        let ticket = progress.chunk(at, length);
        Chunk {
            start,
            length,
            large,
            call: Box::pin(async move {
                self.tree
                    .request(
                        Request::new(
                            command::WRITE_ANDX,
                            self.tree.tid(),
                            self.tree.uid(),
                            request.encode_body()?,
                        )
                        .outliving(ticket),
                    )
                    .await
            }),
        }
    }

    /// Sets the file's length, on a handle opened for writing.
    pub(crate) async fn set_len(&self, length: u64) -> Result<()> {
        let request = TransactionRequest::trans2(
            info::SUBCOMMAND_SET_FILE_INFORMATION,
            info::set_file_parameters(self.fid, info::set_level::END_OF_FILE_INFORMATION),
            length.to_le_bytes().to_vec(),
        );
        let reply = tree::transaction(&self.tree, request, "TRANS2_SET_FILE_INFORMATION").await?;
        if reply.status() != NtStatus::SUCCESS {
            return Err(self.tree.refused(reply.status()));
        }
        Ok(())
    }

    /// Releases the handle, reporting the failure of the round trip.
    pub(crate) async fn close(&self) -> Result<()> {
        let request = wire_file::CloseRequest {
            fid: self.fid,
            last_time_modified: tree::CLOSE_LEAVES_THE_TIME_ALONE,
        };
        self.tree
            .checked(Request::new(
                command::CLOSE,
                self.tree.tid(),
                self.tree.uid(),
                request.encode_body()?,
            ))
            .await?;
        Ok(())
    }
}

/// One chunk on the wire, and where in the caller's span it belongs.
struct Chunk<'a> {
    start: usize,
    length: usize,
    /// Whether it was issued before the connection was recorded small-buffer. A
    /// chunk issued at the small size already has no second attempt to make.
    large: bool,
    call: Pin<Box<dyn Future<Output = Result<Reply>> + Send + 'a>>,
}

/// Waits for whichever outstanding chunk answers first, and takes it out.
///
/// Written by hand rather than reached for from a combinator crate: the depth is
/// four, so polling each in turn costs nothing, and a `Stream` or a `FuturesUnordered`
/// would put a pre-1.0 dependency in the crate for it.
/// Polls the outstanding chunks and returns the first that answers.
///
/// It stops at the first `Poll::Ready`, leaving higher-index futures unpolled —
/// and a chunk's request is not sent until its future is first polled, so that
/// would serialise a batch if it could happen. It cannot: every chunk pends on
/// its first poll, having only just been issued, so all of them are dispatched
/// before any is ready. The note is here because the other reading is the
/// natural one.
async fn first_answered<'a>(issued: &mut Vec<Chunk<'a>>) -> (Chunk<'a>, Result<Reply>) {
    std::future::poll_fn(|context| {
        for index in 0..issued.len() {
            if let Poll::Ready(answer) = issued[index].call.as_mut().poll(context) {
                let chunk = issued.remove(index);
                return Poll::Ready((chunk, answer));
            }
        }
        Poll::Pending
    })
    .await
}

/// What a read can fail with that no status names.
#[derive(Debug, thiserror::Error)]
enum ReadError {
    /// Two chunks answered for the same bytes, which cannot happen against a
    /// server that answers what it was asked.
    #[error(
        "a read chunk returned {length} bytes at {at}, which another chunk had already covered"
    )]
    Overlapping {
        /// Where in the span.
        at: usize,
        /// How many bytes.
        length: usize,
    },
}

/// What a write can fail with that no status names.
#[derive(Debug, thiserror::Error)]
enum WriteError {
    /// A chunk the server took nothing of. Another attempt at it would loop.
    #[error("the server acknowledged none of the {length} bytes offered at {at}")]
    NoProgress {
        /// Where in the span.
        at: usize,
        /// How many bytes were offered.
        length: usize,
    },
}

/// An open file.
///
/// Reads and writes take an absolute offset and `&self`, so concurrent
/// operations on one handle are possible — which matters on a pipelining
/// transport.
#[derive(Debug)]
pub struct File {
    handle: Handle,
    /// The length, known at open from `NT_CREATE_ANDX`'s `EndOfFile` and
    /// updated on write and on `set_len`. **It is a hint, never a gate**: reads
    /// are never short-circuited against it.
    len: AtomicU64,
    /// Where the writer adapter starts, which `append` sets to the length as
    /// observed at open.
    append_at: Option<u64>,
    closed: AtomicBool,
}

impl File {
    pub(crate) fn new(tree: Arc<TreeInner>, fid: u16, len: u64, append: bool) -> Self {
        Self {
            handle: Handle { tree, fid },
            len: AtomicU64::new(len),
            append_at: append.then_some(len),
            closed: AtomicBool::new(false),
        }
    }

    /// The file's length as this handle last observed it.
    ///
    /// Infallible and synchronous, as `len()` is everywhere else in Rust: the
    /// open reported it, so it is not a round trip. It is a hint — `Tree::metadata`
    /// is what goes to the server for callers who need fresh data.
    pub fn len(&self) -> u64 {
        self.len.load(Ordering::Relaxed)
    }

    /// Whether the file is empty, as this handle last observed it.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The handle the server assigned.
    pub fn fid(&self) -> u16 {
        self.handle.fid
    }

    /// Fills `buffer` from `offset`, or fails.
    ///
    /// A span it cannot fill is an error, and end of file is what a request for
    /// bytes the file does not hold produces. A caller that wants a count reads
    /// through [`File::into_reader`], whose `AsyncRead` reports end of file as
    /// `AsyncRead` does everywhere.
    pub async fn read_exact_at(&self, buffer: &mut [u8], offset: u64) -> Result<()> {
        let depth = if buffer.len() >= READ_PIPELINE_THRESHOLD {
            PIPELINE_DEPTH
        } else {
            1
        };
        let wanted = buffer.len();
        let fill = self.handle.read_span(buffer, offset, depth).await?;
        match fill.covered.gap(wanted) {
            None => Ok(()),
            Some((at, end)) => Err(Error::UnfilledSpan {
                at,
                length: end - at,
            }),
        }
    }

    /// Writes the whole of `data` at `offset`, or fails.
    ///
    /// It returns nothing on success, which it reaches only when every byte has
    /// been acknowledged. When it fails instead, the error carries the
    /// contiguous acknowledged prefix — a lower bound on what reached the
    /// server.
    ///
    /// `progress` is how a caller that **drops** this future learns the same
    /// number: a dropped future yields no value, so nothing reaches the caller
    /// on that path unless a handle was passed to outlive it.
    pub async fn write_all_at(
        &self,
        data: &[u8],
        offset: u64,
        progress: Option<WriteProgress>,
    ) -> Result<()> {
        let progress = progress.unwrap_or_default();
        let issuing = progress.register(offset)?;
        let depth = if data.len() >= WRITE_PIPELINE_THRESHOLD {
            PIPELINE_DEPTH
        } else {
            1
        };
        let written = self.handle.write_span(data, offset, depth, &progress).await;
        drop(issuing);
        if written.is_ok() {
            self.grew_to(offset + data.len() as u64);
        }
        written
    }

    /// Sets the file's length.
    ///
    /// The handle has to have been opened for writing, the level altering the
    /// file's length.
    pub async fn set_len(&self, length: u64) -> Result<()> {
        self.handle.set_len(length).await?;
        self.len.store(length, Ordering::Relaxed);
        Ok(())
    }

    /// Releases the handle, reporting whether the round trip succeeded.
    ///
    /// It consumes the handle, so using a closed one is a compile error rather
    /// than a runtime one. A `File` behind an `Arc` cannot reach this at all and
    /// is released by the `Drop` path instead.
    pub async fn close(self) -> Result<()> {
        self.closed.store(true, Ordering::Relaxed);
        self.handle.close().await
    }

    /// A cursor-carrying [`tokio::io::AsyncRead`] over this file.
    ///
    /// Without it the crate cannot be used with `tokio::io::copy`, `BufReader`,
    /// `read_to_end` or anything else that accepts `impl AsyncRead`. It buffers
    /// internally and pipelines its fill unconditionally, whatever size the
    /// caller's `read()` asks for: measuring a threshold against what
    /// `tokio::io::copy` hands it 8 KiB at a time would make the read-ahead dead
    /// code on precisely the case it exists for.
    pub fn into_reader(self) -> FileReader {
        FileReader::new(self)
    }

    /// A cursor-carrying [`tokio::io::AsyncWrite`] over this file.
    ///
    /// It takes the optional [`WriteProgress`] here because `AsyncWrite`'s
    /// per-call signature has nowhere to put one and an adapter is built once —
    /// and it returns a `Result` for that argument's sake, a handle that already
    /// serves a write being refused here as it is at [`File::write_all_at`].
    pub fn into_writer(self, progress: Option<WriteProgress>) -> Result<FileWriter> {
        FileWriter::new(self, progress)
    }

    /// Reads the whole file, as `Tree::read` does.
    ///
    /// This is the one place the fill-or-error rule does not apply: the buffer is
    /// sized from the length the open reported, so a file another writer
    /// truncates in between answers short at the far end, and that is end of
    /// file here rather than an error.
    pub(crate) async fn read_to_end(&self) -> Result<Vec<u8>> {
        let mut buffer = vec![0; self.len() as usize];
        let depth = if buffer.len() >= READ_PIPELINE_THRESHOLD {
            PIPELINE_DEPTH
        } else {
            1
        };
        let fill = self.handle.read_span(&mut buffer, 0, depth).await?;
        // The exemption is for a short *far end* and nothing else. A hole with
        // covered bytes beyond it is a different condition — truncating to the
        // prefix would discard everything after it and report success, which is
        // the silent truncation this exemption was never meant to license.
        let prefix = fill.covered.prefix();
        if let Some((at, end)) = fill.covered.gap(buffer.len())
            && end < buffer.len()
        {
            return Err(Error::UnfilledSpan {
                at,
                length: end - at,
            });
        }
        buffer.truncate(prefix);
        Ok(buffer)
    }

    /// The cursor a writer adapter starts at: the length observed at open where
    /// the handle was opened for appending, and zero otherwise.
    pub(crate) fn start_of_writes(&self) -> u64 {
        self.append_at.unwrap_or(0)
    }

    pub(crate) fn handle(&self) -> &Handle {
        &self.handle
    }

    /// Records a write's far end, the length being a hint this keeps current.
    pub(crate) fn grew_to(&self, end: u64) {
        self.len.fetch_max(end, Ordering::Relaxed);
    }
}

impl Drop for File {
    fn drop(&mut self) {
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
        // `Drop` can neither await the round trip nor report its failure, so the
        // close is handed to the connection actor best-effort, on its own
        // unbounded channel and ahead of whatever the caller does next.
        let request = wire_file::CloseRequest {
            fid: self.handle.fid,
            last_time_modified: tree::CLOSE_LEAVES_THE_TIME_ALONE,
        };
        match request.encode_body() {
            Ok(body) => self.handle.tree.connection().enqueue_close(Request::new(
                command::CLOSE,
                self.handle.tree.tid(),
                self.handle.tree.uid(),
                body,
            )),
            Err(error) => debug!("a dropped file's close could not be encoded: {error}"),
        }
    }
}
