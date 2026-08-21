//! An asynchronous SMB1/CIFS client for legacy file servers that speak nothing newer.
//!
//! SMB1 is frozen and deprecated. This crate exists because some servers still
//! speak nothing else, and because the alternatives in the Rust ecosystem do
//! not cover the dialect: the canonical SMB crate implements SMB2/SMB3 only,
//! and the most-downloaded alternative is a GPLv3 FFI wrapper around
//! libsmbclient. A caller reaches a file through `Client` → `Tree` → `File`,
//! and that is the whole opening sequence.
//!
//! # Security
//!
//! **This crate does not sign messages, and SMB1 has no encryption at all.**
//! Neither is an oversight to be worked around by configuration; the first is
//! deliberately deferred and the second the protocol does not offer. Two
//! consequences follow, and a caller should read them before deciding where to
//! point this crate:
//!
//! - **Every byte on the connection is in the clear**, including file contents
//!   and the paths that name them. Anyone on the network path reads them.
//! - **The server is never authenticated.** Because the crate does not sign, it
//!   has no way to establish that the peer answering is the server it dialled,
//!   at any point in the connection's life. A hostile or intermediary peer is
//!   exactly as present after the session setup as before it.
//!
//! Authentication itself is NTLMv2, which does protect the password from
//! anyone merely reading the wire. What it does not do is protect the session
//! that follows. Treat an SMB1 connection as a plaintext channel to an
//! unverified peer, and put it on a network where that is acceptable.
//!
//! The crate is `#![forbid(unsafe_code)]`, every parser an unauthenticated peer
//! can reach is fuzzed, and allocation from untrusted input is bounded
//! wherever it happens.
//!
//! # Runtime
//!
//! The crate is async-only, on [tokio]. SMB1 is a multiplexed protocol —
//! requests carry a 16-bit multiplex ID and responses return out of order — so
//! something must read frames continuously and route each to whichever caller
//! is waiting. Here that is one task per connection, which owns the socket and
//! the table of outstanding requests outright; callers hold cheap handles and
//! await replies. Cancellation is expressed by dropping a future, as it is
//! everywhere else in async Rust.
//!
//! A synchronous caller must either adopt a runtime or block on the futures
//! itself.
//!
//! [tokio]: https://docs.rs/tokio

// The build order in the design document brings the modules up in dependency
// order. The status table comes before all of them, because nothing that names
// a status can be written until it exists.
pub mod status;

// The statuses [MS-CIFS] defines that [MS-ERREF] does not, hand-written beside
// the generated table rather than inside it.
pub mod cifs_status;

// The error type, and the status classification, which the whole crate reaches
// its failures through.
pub mod error;

// The wire layer is the crate's codec and is deliberately not public surface:
// callers reach a file through `Client`, `Tree` and `File`, and every message
// type here is an implementation detail of that path.
//
// Its consumer is the connection actor. The encoders for commands no layer
// issues yet are what still read as dead, and the allow is narrowed to them as
// each build step brings its own into use; the fixture suite is what holds the
// layer to account in the meantime.
mod wire;

pub mod connection;

// Share enumeration: RAP and DCE/RPC `srvsvc`, and the two named-pipe
// transports underneath the second. `Client::list_shares` is what reaches it.
pub mod rpc;

pub use error::{Error, Result};
pub use status::NtStatus;
