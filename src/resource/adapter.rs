//! The `AsyncRead` and `AsyncWrite` adapters.
//!
//! Without them the crate cannot be used with `tokio::io::copy`, `BufReader`,
//! `read_to_end`, `ReaderStream`, or anything else that accepts
//! `impl AsyncRead` — an isolation that would cost more than the cursor saves.
//!
//! **Both buffer internally, and both pipeline unconditionally.**
//! `tokio::io::copy`'s default 8 KiB buffer would otherwise reach the transport
//! one 8 KiB read at a time and be slower than a hand-written loop, and the
//! 128 KiB and 256 KiB thresholds that gate a one-shot call's pipelining do not
//! govern an adapter: its unit of work is the whole read-ahead fill and not the
//! size of the caller's `read()`. Measuring a threshold against what
//! `tokio::io::copy` hands it would make the read-ahead dead code on precisely
//! the case it exists for, a large file streamed through the adapter.
//!
//! **The read-ahead is a number of outstanding chunks and not a byte size**: a
//! byte figure barely clears one chunk against a server taking 130,048-byte
//! reads, so it would pipeline to a depth of about one and defeat the reason the
//! adapter buffers at all.
//!
//! **The reader reads end of file off the wire rather than off a count.** It
//! drives the same chunk loop the rest of the crate does, so it observes the
//! terminal condition itself — a short far end, a zero-length reply, or
//! `STATUS_END_OF_FILE` — and no public count-returning method has to exist for
//! it to have one.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::Result;

use super::file::{File, Handle};
use super::progress::{Issuing, WriteProgress};

/// A boxed operation in flight. It owns everything it touches, because it
/// outlives every borrow the adapter could lend it.
type InFlight<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// A fill in flight: the bytes it brought back, and whether it reached the end.
type Filling = InFlight<Result<(Vec<u8>, bool)>>;

/// A flush in flight, which hands the buffer back for the next one to reuse.
type Flushing = InFlight<(Vec<u8>, Result<()>)>;

/// A cursor-carrying [`AsyncRead`] over a file.
pub struct FileReader {
    file: File,
    handle: Handle,
    cursor: u64,
    depth: usize,
    /// What the last fill brought back, and how much of it the caller has taken.
    buffer: Vec<u8>,
    taken: usize,
    at_end: bool,
    filling: Option<Filling>,
}

impl std::fmt::Debug for FileReader {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileReader")
            .field("fid", &self.file.fid())
            .field("cursor", &self.cursor)
            .field("buffered", &(self.buffer.len() - self.taken))
            .field("at_end", &self.at_end)
            .finish()
    }
}

impl FileReader {
    pub(crate) fn new(file: File) -> Self {
        let handle = file.handle().clone();
        let depth = handle.tree.read_ahead();
        Self {
            file,
            handle,
            cursor: 0,
            depth,
            buffer: Vec::new(),
            taken: 0,
            at_end: false,
            filling: None,
        }
    }

    /// Gives the [`File`] back, so the handle can still be closed explicitly and
    /// its failure still reported.
    ///
    /// Without a way back the only release path for an adapter-owned handle is
    /// `Drop`, arriving silently on the ordinary path — `into_reader()` being how
    /// a caller reaches `tokio::io::copy`.
    pub async fn into_inner(self) -> Result<File> {
        Ok(self.file)
    }

    /// Where the next read starts.
    pub fn position(&self) -> u64 {
        self.cursor
    }
}

impl AsyncRead for FileReader {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let reader = self.get_mut();
        loop {
            let held = reader.buffer.len() - reader.taken;
            if held > 0 {
                let taking = held.min(buffer.remaining());
                buffer.put_slice(&reader.buffer[reader.taken..reader.taken + taking]);
                reader.taken += taking;
                return Poll::Ready(Ok(()));
            }
            if reader.at_end {
                // End of file, reported the way `AsyncRead` reports it
                // everywhere: no bytes and no error.
                return Poll::Ready(Ok(()));
            }

            let filling = reader.filling.get_or_insert_with(|| {
                let handle = reader.handle.clone();
                let cursor = reader.cursor;
                let depth = reader.depth;
                Box::pin(async move {
                    let size = handle.tree.connection().read_chunk_size().max(1) * depth;
                    let mut span = vec![0; size];
                    let fill = handle.read_span(&mut span, cursor, depth).await?;
                    // The contiguous prefix and not the total covered: the
                    // adapter hands bytes back in order, so a hole is the end of
                    // what it can serve from this fill.
                    let held = fill.covered.prefix();
                    span.truncate(held);
                    Ok((span, fill.at_end || held == 0))
                })
            });
            let filled = ready!(filling.as_mut().poll(context));
            reader.filling = None;
            let (span, at_end) = filled.map_err(io::Error::from)?;
            reader.cursor += span.len() as u64;
            reader.buffer = span;
            reader.taken = 0;
            reader.at_end = at_end;
        }
    }
}

/// A cursor-carrying [`AsyncWrite`] over a file.
pub struct FileWriter {
    file: File,
    handle: Handle,
    progress: WriteProgress,
    /// Says the write is still issuing, so the progress handle's completion
    /// signal cannot fire while the adapter lives. It drops with the adapter,
    /// which a caller abandoning one does as surely as a caller finishing.
    issuing: Option<Issuing>,
    cursor: u64,
    capacity: usize,
    depth: usize,
    buffer: Vec<u8>,
    flushing: Option<Flushing>,
    /// The length the file reaches if the flush in progress succeeds.
    pending_length: Option<u64>,
}

impl std::fmt::Debug for FileWriter {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FileWriter")
            .field("fid", &self.file.fid())
            .field("cursor", &self.cursor)
            .field("buffered", &self.buffer.len())
            .finish()
    }
}

impl FileWriter {
    pub(crate) fn new(file: File, progress: Option<WriteProgress>) -> Result<Self> {
        let handle = file.handle().clone();
        let depth = handle.tree.read_ahead();
        let cursor = file.start_of_writes();
        let progress = progress.unwrap_or_default();
        // A handle that already serves a write is refused here as it is at
        // `write_all_at`: a prefix computed across two writes to different
        // offsets means nothing.
        let issuing = progress.register(cursor)?;
        let capacity = handle.tree.connection().write_chunk_size().max(1) * depth;
        Ok(Self {
            file,
            handle,
            progress,
            issuing: Some(issuing),
            cursor,
            capacity,
            depth,
            buffer: Vec::with_capacity(capacity),
            flushing: None,
            pending_length: None,
        })
    }

    /// Where the next write lands.
    pub fn position(&self) -> u64 {
        self.cursor
    }

    /// Flushes what is buffered and gives the [`File`] back.
    ///
    /// It awaits and it can fail because the adapter holds buffered bytes that
    /// have not reached the server: an infallible synchronous `into_inner()`
    /// would discard them with nothing returned to say so.
    pub async fn into_inner(mut self) -> Result<File> {
        self.flush_buffered().await?;
        self.issuing = None;
        Ok(self.file)
    }

    /// Applies what a finished flush earned: the length it wrote, and only if
    /// it wrote it.
    ///
    /// Both flush paths come through here. The accounting was written twice
    /// once, and only one copy was right — an `into_inner()` after a buffered
    /// write reported a length of zero for bytes the server had acknowledged,
    /// because the path it takes never applied the pending length at all.
    fn settle(&mut self, outcome: &Result<()>) {
        if let (Ok(()), Some(length)) = (outcome, self.pending_length.take()) {
            self.file.grew_to(length);
        }
    }

    /// Writes whatever is buffered.
    async fn flush_buffered(&mut self) -> Result<()> {
        if let Some(mut flushing) = self.flushing.take() {
            let (buffer, outcome) =
                std::future::poll_fn(|context| flushing.as_mut().poll(context)).await;
            self.buffer = buffer;
            self.buffer.clear();
            self.settle(&outcome);
            outcome?;
        }
        if self.buffer.is_empty() {
            return Ok(());
        }
        let span = std::mem::take(&mut self.buffer);
        let at = self.cursor;
        let outcome = self
            .handle
            .write_span(&span, at, self.depth, &self.progress)
            .await;
        self.cursor += span.len() as u64;
        self.pending_length = Some(self.cursor);
        self.settle(&outcome);
        self.buffer = span;
        self.buffer.clear();
        outcome
    }

    /// Starts writing what is buffered, so that the caller's next `write` does
    /// not have to wait for it.
    fn start_flush(&mut self) {
        if self.buffer.is_empty() || self.flushing.is_some() {
            return;
        }
        let span = std::mem::take(&mut self.buffer);
        let at = self.cursor;
        // The cursor advances here and the file's length does not. The cursor
        // has to: the caller's next `write` buffers at the position after this
        // flush, which is what lets the two overlap at all. The length is a
        // claim about what the server holds, so it waits until the flush says
        // the server holds it — otherwise a failed flush leaves `File::len`
        // over-reporting bytes that never landed.
        self.cursor += span.len() as u64;
        let grown_to = self.cursor;
        let handle = self.handle.clone();
        let progress = self.progress.clone();
        let depth = self.depth;
        self.pending_length = Some(grown_to);
        self.flushing = Some(Box::pin(async move {
            let outcome = handle.write_span(&span, at, depth, &progress).await;
            (span, outcome)
        }));
    }

    /// Drives a flush already in progress.
    fn poll_flushing(&mut self, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let Some(flushing) = self.flushing.as_mut() else {
            return Poll::Ready(Ok(()));
        };
        let (buffer, outcome) = ready!(flushing.as_mut().poll(context));
        self.flushing = None;
        self.buffer = buffer;
        self.buffer.clear();
        self.settle(&outcome);
        Poll::Ready(outcome.map_err(io::Error::from))
    }
}

impl AsyncWrite for FileWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let writer = self.get_mut();
        ready!(writer.poll_flushing(context))?;
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let room = writer.capacity - writer.buffer.len();
        let taking = room.min(data.len());
        writer.buffer.extend_from_slice(&data[..taking]);
        if writer.buffer.len() >= writer.capacity {
            writer.start_flush();
        }
        Poll::Ready(Ok(taking))
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let writer = self.get_mut();
        loop {
            ready!(writer.poll_flushing(context))?;
            if writer.buffer.is_empty() {
                return Poll::Ready(Ok(()));
            }
            writer.start_flush();
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_flush(context)
    }
}
