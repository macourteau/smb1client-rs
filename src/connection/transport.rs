//! The test seam: a connection actor over any stream.
//!
//! **This is public surface and it is not behind a feature flag.** Captured
//! fixtures are static bytes, so they can prove parsing and nothing about
//! timing — and every capture in the corpus has exactly one request outstanding
//! at a time, so a replay harness alone cannot distinguish a correct
//! implementation from several broken ones. Three of the crate's four
//! invariants are timing properties, and the fourth's distinguishing content —
//! coverage of a reply's declared ranges rather than a sum of byte counts —
//! needs an overlapping or gapped fragment, which no capture holds.
//!
//! So the actor is constructible over an arbitrary [`AsyncRead`] +
//! [`AsyncWrite`], with the negotiated parameters injected rather than reached
//! through a real handshake. A feature flag would add a second build
//! configuration for CI to test, when the point of the seam is that the
//! deterministic tests drive the same code path a consumer gets.
//!
//! The ordering the design fixes is untouched by it: the handshake still
//! completes before the actor takes the stream, and what a test replaces is the
//! stream, not the sequence.
//!
//! ```no_run
//! use smb1client::connection::{Negotiated, Timeouts, transport};
//!
//! # async fn example(stream: tokio::io::DuplexStream) {
//! let connection = transport::spawn(
//!     stream,
//!     Negotiated {
//!         max_mpx_count: 50,
//!         max_buffer_size: 65_535,
//!         capabilities: 0,
//!     },
//!     Timeouts::default(),
//!     false,
//! );
//! # let _ = connection;
//! # }
//! ```

use tokio::io::{AsyncRead, AsyncWrite};

use super::{Connection, MIN_BUFFER_SIZE, Negotiated, Timeouts};

/// Puts a connection actor on an already-negotiated, already-authenticated
/// stream, and returns a handle on it.
///
/// The actor runs as a spawned task, so this must be called from inside a tokio
/// runtime. It ends when every handle on the connection has been dropped, or
/// when the connection fails.
///
/// `dump_bytes` is the operator's byte-level dump toggle for this run, off
/// unless it was turned on deliberately: a dump of a listing or a read reply
/// carries filenames and file contents. It does not reach `SESSION_SETUP_ANDX`,
/// whose byte section the tracer redacts whatever this says.
pub fn spawn<S>(
    stream: S,
    negotiated: Negotiated,
    timeouts: Timeouts,
    dump_bytes: bool,
) -> Connection
where
    S: AsyncRead + AsyncWrite + Send + 'static,
{
    assert!(
        negotiated.max_buffer_size >= MIN_BUFFER_SIZE,
        "MaxBufferSize {} is below the {MIN_BUFFER_SIZE}-byte SMB1 minimum",
        negotiated.max_buffer_size,
    );
    super::actor::spawn(stream, negotiated, timeouts, dump_bytes)
}
