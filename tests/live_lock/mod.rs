//! One live dial at a time.
//!
//! Windows 11 24H2 allows a single SMB1 connection per client host: dialled in
//! parallel the later handshakes break, and dialled back to back they succeed
//! but leave the earlier connection dead. Every suite here dials several times
//! over. Cargo runs test binaries one after another, but the tests inside one
//! binary run in parallel threads, so this is the piece that makes the live
//! suite serial — without it the filesystem suite reports five of six failed
//! against Windows with `Broken pipe` and `Connection reset`.
//!
//! The lock is async so that a test waiting its turn parks rather than blocking
//! the thread its runtime is on. Each `#[tokio::test]` builds its own runtime,
//! and `tokio::sync::Mutex` does not care which one a waiter is parked in: the
//! guard's release wakes the waiting runtime through its own waker. It also
//! does not poison, so a test that panics mid-dial hands the turn on rather
//! than failing every test after it for a reason none of them caused.

use tokio::sync::{Mutex, MutexGuard};

static DIAL: Mutex<()> = Mutex::const_new(());

/// Waits until no other test in this binary is talking to the server.
pub async fn one_at_a_time() -> MutexGuard<'static, ()> {
    DIAL.lock().await
}
