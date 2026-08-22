//! Open handles: [`File`], the lazily-paged listing iterator [`ReadDir`], and
//! the `AsyncRead`/`AsyncWrite` adapters built on a file.
//!
//! **`close()` consumes the handle**, so using a closed handle is a compile
//! error rather than a runtime one, and it is `async` and fallible for callers
//! who need to know that the release succeeded. **`Drop` enqueues a best-effort
//! close** and logs failures: it neither spawns a task nor requires a runtime to
//! be running, because it hands the close to the connection actor over a
//! channel, which is a plain non-blocking operation.
//!
//! Send order is guaranteed and completion order is not. The close is queued
//! ahead of whatever the caller does next on that connection, but the server is
//! working on up to the admission limit of requests at once and may still be
//! finishing the close when it starts the operation behind it — so dropping a
//! listing and then deleting the directory it enumerated is safe only when the
//! operation **awaits** the close reply, which is what
//! [`Tree::remove_dir_all`](crate::Tree::remove_dir_all) does.

mod adapter;
mod file;
mod listing;
mod progress;

pub use adapter::{FileReader, FileWriter};
pub use file::{File, PIPELINE_DEPTH, READ_PIPELINE_THRESHOLD, WRITE_PIPELINE_THRESHOLD};
pub use listing::{DirEntry, ReadDir};
pub use progress::WriteProgress;

/// How many chunks an adapter keeps outstanding by default.
///
/// It is a memory-versus-throughput trade — four chunks is 508 KiB where the
/// large-read capability is present — and a consumer holding adapters over many
/// files at once pays it per file.
pub const DEFAULT_READ_AHEAD: usize = 4;
