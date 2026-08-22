//! `WriteProgress`: how a caller that drops a write future learns how much of
//! it reached the server.
//!
//! A dropped future yields no value — no count and no error — so nothing reaches
//! the caller on that path, ever. The caller constructs one of these, keeps its
//! own clone and passes another to the call, so that the handle outlives the
//! dropped future and can be read afterwards. It is `Clone` over a shared inner
//! value, and that is forced rather than chosen: ranges are recorded after the
//! caller's future has been dropped, so a borrow could not outlive it. The call
//! therefore takes the handle **by value**.
//!
//! **It is not a bare counter.** Replies land out of order on a pipelining
//! transport, and a scalar cannot say which bytes reached the server. The handle
//! carries the acknowledged ranges, and **a range is recorded from the reply
//! rather than from the request**: the chunk's offset, and the count the
//! `WRITE_ANDX` response acknowledges, which may be fewer bytes than the chunk
//! asked to write. Recording what was requested would overstate what landed,
//! which is the one thing the prefix exists to get right.
//!
//! **One handle serves one write**, for its whole lifetime and not merely one
//! write at a time: a prefix computed across two writes to different offsets
//! means nothing, and a completion signal that waits for both answers neither. A
//! second registration is an `Err` rather than a panic, this being recoverable
//! caller misuse.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use tokio::sync::watch;
use tracing::debug;

use crate::connection::{Coverage, Reply, RequestOutcome};
use crate::error::{Error, Result};
use crate::wire::io::WriteAndxResponse;

/// The acknowledged ranges of one write, and the signal that says they are
/// final.
#[derive(Debug, Clone)]
pub struct WriteProgress {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    state: Mutex<State>,
    /// `true` once the write's own requests have all left the group. A watch
    /// rather than a notify, so that a waiter arriving after the signal is not
    /// left waiting for one that has already fired.
    settled: watch::Sender<bool>,
}

#[derive(Debug)]
struct State {
    /// The offset the write began at. Ranges are recorded against it, so the
    /// prefix is a length rather than an offset.
    base: u64,
    covered: Coverage,
    /// The chunk group: which of this write's requests have not yet left it.
    outstanding: usize,
    /// Whether the write is still issuing chunks. It goes false when the
    /// issuing guard drops — which a cancelled future does as surely as a
    /// finished one, and which is what keeps the group from reading as empty
    /// before the first chunk is issued.
    issuing: bool,
    registered: bool,
    /// The prefix, once declared final. A prefix already declared final may not
    /// grow afterwards: a caller may have resumed from it.
    final_prefix: Option<u64>,
}

impl Default for WriteProgress {
    fn default() -> Self {
        Self::new()
    }
}

impl WriteProgress {
    /// A handle for one write.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Inner {
                state: Mutex::new(State {
                    base: 0,
                    covered: Coverage::default(),
                    outstanding: 0,
                    issuing: false,
                    registered: false,
                    final_prefix: None,
                }),
                settled: watch::channel(false).0,
            }),
        }
    }

    /// The contiguous acknowledged prefix, and a lower bound on what reached the
    /// server.
    ///
    /// Before the completion signal it is a lower bound; after it, it is final,
    /// whatever ended the write. It is never the total that landed: if a middle
    /// chunk fails while later ones succeed the two differ, and only the prefix
    /// is safe to resume from — the first `written()` bytes are on the server
    /// and nothing is claimed beyond them.
    pub fn written(&self) -> u64 {
        let state = self.lock();
        state
            .final_prefix
            .unwrap_or_else(|| state.covered.prefix() as u64)
    }

    /// Waits until every chunk the write registered has left the group.
    ///
    /// It keys on the group and not on the connection's request table: a lapsed
    /// request leaves the group at the lapse while it stays in the table holding
    /// its multiplex id, and waiting on the table would hang here on exactly the
    /// case this handle exists for. Orphaned has three exits — an arrival that
    /// ends the request, the request lapsing, and the connection dying — and the
    /// signal covers all three, so a caller awaiting it is never left waiting on
    /// a connection that has gone.
    pub async fn completed(&self) {
        let mut settled = self.inner.settled.subscribe();
        while !*settled.borrow_and_update() {
            if settled.changed().await.is_err() {
                return;
            }
        }
    }

    /// Claims this handle for one write, which begins at `base`.
    ///
    /// The guard is what says the write is still issuing; dropping it — which a
    /// cancelled future does as surely as a finished one — is what lets the
    /// group settle.
    pub(crate) fn register(&self, base: u64) -> Result<Issuing> {
        let mut state = self.lock();
        if state.registered {
            return Err(Error::ProgressInUse);
        }
        state.registered = true;
        state.issuing = true;
        state.base = base;
        drop(state);
        Ok(Issuing {
            inner: self.inner.clone(),
        })
    }

    /// A ticket for one chunk, which enters the group here and leaves it when
    /// the request ends.
    pub(crate) fn chunk(&self, offset: u64) -> Arc<Chunk> {
        self.lock().outstanding += 1;
        Arc::new(Chunk {
            inner: self.inner.clone(),
            offset,
            applied: AtomicBool::new(false),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Inner {
    /// Declares the prefix final once the write has stopped issuing and every
    /// chunk has left the group.
    fn settle(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if state.issuing || state.outstanding > 0 || state.final_prefix.is_some() {
            return;
        }
        let prefix = state.covered.prefix() as u64;
        state.final_prefix = Some(prefix);
        drop(state);
        // `send_replace` rather than `send`: a `watch` sender with no receiver
        // yet refuses a `send` and leaves the value untouched, so a caller that
        // has not reached `completed()` when the last chunk lands would wait for
        // a signal that had already been withheld.
        self.settled.send_replace(true);
    }
}

/// Says the write is still issuing chunks. It lives in the write future, so a
/// caller dropping that future drops this too.
#[derive(Debug)]
pub(crate) struct Issuing {
    inner: Arc<Inner>,
}

impl Drop for Issuing {
    fn drop(&mut self) {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .issuing = false;
        self.inner.settle();
    }
}

/// One chunk's membership of the group, and what it records when it ends.
///
/// The connection actor applies this when the request ends, whichever way it
/// ends and whether or not the caller is still waiting — which is what makes the
/// drop path and the ordinary path record the same thing.
#[derive(Debug)]
pub(crate) struct Chunk {
    inner: Arc<Inner>,
    offset: u64,
    /// Whether the outcome has been applied. A chunk whose request never
    /// reaches the actor at all — the future built and then dropped when the
    /// caller gave up — leaves the group here instead, so the group can never
    /// hold a member nothing will ever answer for.
    applied: AtomicBool,
}

impl Chunk {
    /// Takes this chunk out of the group, once.
    fn leave(&self) {
        if self.applied.swap(true, Ordering::Relaxed) {
            return;
        }
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .outstanding -= 1;
        self.inner.settle();
    }
}

impl Drop for Chunk {
    fn drop(&mut self) {
        if !self.applied.load(Ordering::Relaxed) {
            debug!(
                offset = self.offset,
                "a write chunk was abandoned before it reached the wire"
            );
            self.leave();
        }
    }
}

impl RequestOutcome for Chunk {
    fn ended(&self, outcome: std::result::Result<&Reply, &crate::connection::Error>) {
        {
            let mut state = self
                .inner
                .state
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match outcome {
                Ok(reply) => match acknowledged(reply) {
                    Some(count) if count > 0 => {
                        let at = self.offset.saturating_sub(state.base) as usize;
                        if !state.covered.cover(at, count) {
                            debug!(
                                offset = self.offset,
                                count, "a write chunk acknowledged bytes already acknowledged"
                            );
                        }
                    }
                    _ => debug!(offset = self.offset, "a write chunk acknowledged nothing"),
                },
                Err(error) => debug!(
                    offset = self.offset,
                    "a write chunk ended without an acknowledgement: {error}"
                ),
            }
        }
        self.leave();
    }
}

/// What a `WRITE_ANDX` reply acknowledges, or `None` where it acknowledged
/// nothing this crate can read.
fn acknowledged(reply: &Reply) -> Option<usize> {
    if reply.status() != crate::status::NtStatus::SUCCESS {
        return None;
    }
    WriteAndxResponse::decode(reply.parsed())
        .ok()
        .map(|response| response.count as usize)
}
