//! The crate's error type, and the one place an NT status becomes an
//! [`io::ErrorKind`].
//!
//! Two accessors carry the whole of what a caller needs. [`Error::kind`]
//! answers the question a caller can act on generically — did this fail because
//! the file does not exist? — and [`Error::status`] answers the one it cannot,
//! by handing back the raw status the server sent. The classification is
//! narrow on purpose: a handful of statuses reach a named [`io::ErrorKind`] and
//! every other one reaches [`io::ErrorKind::Other`] with its status intact, so
//! a caller can match a status this crate never anticipated.

use std::io;

use crate::cifs_status::Named;
use crate::status::NtStatus;
use crate::wire::WireError;

/// A shorthand for a result carrying this crate's [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// Everything this crate can fail with.
///
/// Match on the variants where the distinction matters, or call [`Error::kind`]
/// for the `std` classification and let `?` convert the error into an
/// [`io::Error`] where a consumer's own functions return `io::Result`.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The server refused the operation, and this is the status it refused it
    /// with.
    ///
    /// [`Error::kind`] classifies the common ones; the rest reach
    /// [`io::ErrorKind::Other`] with the status still reachable through
    /// [`Error::status`].
    #[error("the server refused the request: {}", Named(*.0))]
    Status(NtStatus),

    /// The server refused a transaction for want of resources, and the likely
    /// cause is a transaction larger than that server accepts.
    ///
    /// Likely rather than certain: a server genuinely out of resources answers
    /// `STATUS_INSUFF_SERVER_RESOURCES` too, and so does one refusing a request
    /// for having too many outstanding at once. The status text points at
    /// server capacity, which is why the size is named here instead — it is the
    /// cause that is worth checking first, and the one that is invisible from
    /// the status alone. Nothing is retried at a smaller size, so which size a
    /// server accepts stays a question the caller can answer.
    #[error(
        "the server refused a transaction for want of resources, which most often means \
         a request larger than it accepts"
    )]
    TransactionRefused,

    /// A transaction request this crate built was larger than one message may
    /// carry, and it failed here rather than on the wire.
    ///
    /// A long path or a long search pattern is the realistic way to reach this.
    /// The request is neither truncated nor split across messages.
    #[error(
        "{request} needs {size} bytes, which exceeds the {limit}-byte limit on one \
         transaction request"
    )]
    TransactionTooLarge {
        /// The request that did not fit, named as the protocol names it.
        request: &'static str,
        /// The bytes that request needs.
        size: usize,
        /// The bytes one transaction request may carry.
        limit: usize,
    },

    /// The connection this call needed had already died. The *next* call
    /// re-dials; this one does not.
    ///
    /// A re-dial carries no handles across: a file, a listing iterator and a
    /// tree all hold identifiers that mean nothing outside the connection they
    /// were opened on, so an operation on one of them after its connection is
    /// gone fails this way and the caller re-opens what it needs. An operation that failed part-way is not retried
    /// for the caller, because a write is not idempotent and a silent second
    /// attempt would be a guess about what the server already did.
    #[error("the connection was lost; the next call re-dials")]
    ConnectionLost {
        /// The status that said so, where a status did.
        status: Option<NtStatus>,
    },

    /// The server discarded the tree connection this call needed, and nothing
    /// more: the connection, the other trees on it and their handles are all
    /// still good.
    ///
    /// The caller re-opens that one tree. Only handles opened on it are
    /// invalid.
    #[error("the server discarded the tree connection; re-open it to continue")]
    TreeDisconnected,

    /// The dial or the handshake did not finish inside the connect timeout.
    ///
    /// The server may be unreachable, or slow enough that the bound wants
    /// raising.
    #[error("the connect timeout elapsed before the connection was usable")]
    ConnectTimeout,

    /// A request outlived its timing bound with no answer from the server.
    ///
    /// The request is given up on, not cancelled: SMB1 offers no way to
    /// withdraw one, so a reply arriving later is discarded.
    #[error("the server did not answer inside the request's timing bound")]
    RequestTimeout,

    /// The transport failed: the socket, the dial, or the bytes on it.
    #[error("transport failure: {0}")]
    Io(#[from] io::Error),

    /// The server sent a message this crate could not make sense of.
    ///
    /// The source carries what the decoder saw. A caller can do nothing about
    /// it beyond reporting it, which is why the detail is a message rather than
    /// a type to match on.
    #[error("the server sent a message this crate could not decode: {0}")]
    Protocol(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// A path the caller gave was refused before anything reached the wire.
    ///
    /// Absolute paths, paths carrying a null byte, paths that escape the share
    /// root once `.` and `..` are resolved, and UNC paths that name no server
    /// or share are all refused this way.
    #[error("invalid path: {0}")]
    InvalidPath(String),

    /// The server requires message signing, which this crate does not perform.
    ///
    /// It is named on its own because the alternative is an access-denied
    /// failure that sends an operator looking at credentials.
    #[error("the server requires message signing, which this crate does not perform")]
    SigningRequired,

    /// The server logged the client on as a guest rather than as the user the
    /// credentials name, which on many servers is what a wrong password
    /// produces.
    ///
    /// Every operation on such a session would run with whatever rights guests
    /// have, so the session is refused unless guest access is what the caller
    /// asked for.
    #[error("the server logged the client on as a guest rather than as the named user")]
    GuestLogon,

    /// Two ways of performing one operation were both tried and both failed,
    /// and this carries why each did.
    ///
    /// Share enumeration reaches it twice over: RAP giving way to DCE/RPC
    /// `srvsvc`, and inside `srvsvc` a pipe transact giving way to
    /// write-then-read. Both fall-throughs trigger on *any* error from the
    /// first attempt, so the second attempt's own failure often says nothing
    /// about why the first was abandoned — which is why the first is kept
    /// rather than discarded. [`Error::kind`] and [`Error::status`] answer for
    /// the second attempt, that being the one that decided the outcome.
    #[error("{operation} failed both ways it was attempted: {first}; and then: {second}")]
    BothAttemptsFailed {
        /// What was being attempted, named for a reader of the message.
        operation: &'static str,
        /// Why the first way failed.
        first: Box<Error>,
        /// Why the second way failed.
        second: Box<Error>,
    },

    /// The server is one this crate declines to talk to, and the message says
    /// which requirement it failed.
    ///
    /// A missing capability, share-level security, a negotiated buffer below
    /// the SMB1 minimum and a server offering no dialect this crate speaks all
    /// fail this way, at the handshake and before any credentials are sent.
    #[error("the server does not meet this crate's requirements: {0}")]
    UnsupportedServer(String),
}

impl Error {
    /// The `std` classification of this failure.
    ///
    /// This is what replaces a taxonomy of predicates: "did this fail because
    /// the file does not exist?" is answered by four different NT statuses
    /// depending on which server answered, and all four reach
    /// [`io::ErrorKind::NotFound`] here. A status outside every group this
    /// crate classifies reaches [`io::ErrorKind::Other`], which is the common
    /// case rather than the exception — [`Error::status`] is what stays
    /// informative there.
    pub fn kind(&self) -> io::ErrorKind {
        match self {
            Error::Status(status) => status_kind(*status),
            // The size is a guess about a status that says capacity, so the
            // caller is left to act on the message rather than on a kind that
            // would invite a retry the crate deliberately does not perform.
            Error::TransactionRefused => io::ErrorKind::Other,
            Error::TransactionTooLarge { .. } | Error::InvalidPath(_) => {
                io::ErrorKind::InvalidInput
            }
            Error::ConnectionLost { .. } => io::ErrorKind::ConnectionAborted,
            // The tree is gone and the connection is not, so the call needs a
            // tree re-opened rather than anything re-dialled.
            Error::TreeDisconnected => io::ErrorKind::NotConnected,
            Error::ConnectTimeout | Error::RequestTimeout => io::ErrorKind::TimedOut,
            Error::Io(error) => error.kind(),
            Error::Protocol(_) => io::ErrorKind::InvalidData,
            Error::GuestLogon => io::ErrorKind::PermissionDenied,
            Error::SigningRequired | Error::UnsupportedServer(_) => io::ErrorKind::Unsupported,
            // The second attempt is the one that decided the outcome, so it is
            // the one a caller acts on.
            Error::BothAttemptsFailed { second, .. } => second.kind(),
        }
    }

    /// The NT status the server sent, where this failure came from one.
    ///
    /// `None` on a failure that never carried a status — a transport failure, a
    /// decode failure, or anything refused before it reached the wire. A caller
    /// matching a status directly should know that several statuses mean the
    /// same condition on different servers, which is what [`Error::kind`]
    /// exists to spare it.
    pub fn status(&self) -> Option<NtStatus> {
        match self {
            Error::Status(status) => Some(*status),
            Error::TransactionRefused => Some(NtStatus::INSUFF_SERVER_RESOURCES),
            Error::TreeDisconnected => Some(NtStatus::NETWORK_NAME_DELETED),
            Error::ConnectionLost { status } => *status,
            Error::BothAttemptsFailed { second, .. } => second.status(),
            Error::TransactionTooLarge { .. }
            | Error::ConnectTimeout
            | Error::RequestTimeout
            | Error::Io(_)
            | Error::Protocol(_)
            | Error::InvalidPath(_)
            | Error::SigningRequired
            | Error::GuestLogon
            | Error::UnsupportedServer(_) => None,
        }
    }
}

impl From<Error> for io::Error {
    fn from(error: Error) -> Self {
        match error {
            // A transport failure is already an `io::Error`, and wrapping it in
            // another one buries the operating system's own error behind a
            // second layer of source.
            Error::Io(inner) => inner,
            other => io::Error::new(other.kind(), other),
        }
    }
}

impl From<WireError> for Error {
    fn from(error: WireError) -> Self {
        Error::Protocol(Box::new(error))
    }
}

/// Where a status becomes an [`io::ErrorKind`], and the only place it does.
///
/// The named groups below are what a real server actually answers a given
/// condition with, read off the reference library's own predicates
/// (`errors.go`) rather than reasoned about from the names: authentication at
/// `:208-224`, permission at `:325-328`, already-exists at `:370-371` and
/// temporary at `:441-445`. The statuses named in [`NtStatus`] itself are
/// spelled that way; the rest are named here, because the generated table
/// exports codes and a bare `0xC000006D` in a match arm is unreviewable.
///
/// `STATUS_BUFFER_OVERFLOW` is deliberately absent: it arises only on the
/// named-pipe paths, where the read loop consumes it and reads again until the
/// response is whole, so no caller of this crate ever sees it. `STATUS_END_OF_FILE`
/// and `STATUS_NO_MORE_FILES` are absent for the same reason — the read loop and
/// the listing loop respectively read them as an ordinary end rather than as a
/// failure, and neither reaches a caller as an error at all.
fn status_kind(status: NtStatus) -> io::ErrorKind {
    use io::ErrorKind as Kind;

    match status {
        // Which of the four a server answers with depends on the server, not on
        // what went wrong, so a caller matching one of them writes a bug that
        // appears against one server family and not another.
        NtStatus::NO_SUCH_FILE
        | NtStatus::OBJECT_NAME_NOT_FOUND
        | NtStatus::OBJECT_PATH_NOT_FOUND
        | NtStatus::NOT_FOUND => Kind::NotFound,

        NtStatus::DIRECTORY_NOT_EMPTY => Kind::DirectoryNotEmpty,
        NtStatus::NOT_A_DIRECTORY => Kind::NotADirectory,
        // What a server answers a `remove_file` aimed at a directory with,
        // there being no client-side check to refuse it first.
        NtStatus::FILE_IS_A_DIRECTORY => Kind::IsADirectory,
        // A handle the server does not know, which means this crate sent one it
        // should not have or the caller kept one past its life.
        NtStatus::INVALID_HANDLE => Kind::InvalidInput,

        // A sharing violation is a transient conflict with another open handle
        // rather than an authorization failure, and the reference library
        // grouping it with permission failures is overruled deliberately: a
        // caller that retries on busy and gives up on denied needs the two
        // apart.
        NtStatus::SHARING_VIOLATION => Kind::ResourceBusy,

        // What `rename` answers with when the destination exists; it does not
        // overwrite one.
        NtStatus::OBJECT_NAME_COLLISION | STATUS_OBJECT_NAME_EXISTS => Kind::AlreadyExists,

        STATUS_LOGON_FAILURE
        | STATUS_ACCESS_DENIED
        | STATUS_INVALID_LOGON_HOURS
        | STATUS_INVALID_LOGON_TYPE
        | STATUS_LOGON_TYPE_NOT_GRANTED
        | STATUS_LOGON_NOT_GRANTED
        | STATUS_ACCOUNT_DISABLED
        | STATUS_ACCOUNT_EXPIRED
        | STATUS_PASSWORD_EXPIRED
        | STATUS_PASSWORD_MUST_CHANGE
        | STATUS_WRONG_PASSWORD
        | STATUS_NO_SUCH_USER
        | STATUS_INVALID_ACCOUNT_NAME
        | STATUS_INVALID_WORKSTATION
        | STATUS_ACCOUNT_RESTRICTION
        | STATUS_INSUFFICIENT_LOGON_INFO
        | STATUS_SMARTCARD_LOGON_REQUIRED
        | STATUS_PRIVILEGE_NOT_HELD
        | STATUS_NETWORK_ACCESS_DENIED => Kind::PermissionDenied,

        // The conditions that pass: the same kind a sharing violation gets, and
        // for the same reason — this is what a caller keys a retry on.
        STATUS_PENDING
        | STATUS_RETRY
        | STATUS_DEVICE_NOT_READY
        | STATUS_TOO_MANY_SESSIONS
        | STATUS_NETWORK_BUSY => Kind::ResourceBusy,

        // The common case: 1,796 statuses are defined and this classifies a few
        // dozen. `Other` is what `std` reserves for exactly this, and the raw
        // status stays reachable through `Error::status`.
        _ => Kind::Other,
    }
}

// The statuses the groups above are read off, with the names the specification
// gives them. `NtStatus` names the ones the crate reasons about elsewhere; these
// are named nowhere else and are private for that reason.
const STATUS_ACCESS_DENIED: NtStatus = NtStatus::new(0xC000_0022);
const STATUS_INVALID_ACCOUNT_NAME: NtStatus = NtStatus::new(0xC000_0062);
const STATUS_NO_SUCH_USER: NtStatus = NtStatus::new(0xC000_0064);
const STATUS_WRONG_PASSWORD: NtStatus = NtStatus::new(0xC000_006A);
const STATUS_LOGON_FAILURE: NtStatus = NtStatus::new(0xC000_006D);
const STATUS_ACCOUNT_RESTRICTION: NtStatus = NtStatus::new(0xC000_006E);
const STATUS_INVALID_LOGON_HOURS: NtStatus = NtStatus::new(0xC000_006F);
const STATUS_INVALID_WORKSTATION: NtStatus = NtStatus::new(0xC000_0070);
const STATUS_PASSWORD_EXPIRED: NtStatus = NtStatus::new(0xC000_0071);
const STATUS_ACCOUNT_DISABLED: NtStatus = NtStatus::new(0xC000_0072);
const STATUS_INVALID_LOGON_TYPE: NtStatus = NtStatus::new(0xC000_010B);
const STATUS_LOGON_NOT_GRANTED: NtStatus = NtStatus::new(0xC000_0155);
const STATUS_LOGON_TYPE_NOT_GRANTED: NtStatus = NtStatus::new(0xC000_015B);
const STATUS_ACCOUNT_EXPIRED: NtStatus = NtStatus::new(0xC000_0193);
const STATUS_PASSWORD_MUST_CHANGE: NtStatus = NtStatus::new(0xC000_0224);
const STATUS_INSUFFICIENT_LOGON_INFO: NtStatus = NtStatus::new(0xC000_0250);
const STATUS_SMARTCARD_LOGON_REQUIRED: NtStatus = NtStatus::new(0xC000_02FA);
const STATUS_PRIVILEGE_NOT_HELD: NtStatus = NtStatus::new(0xC000_0061);
const STATUS_NETWORK_ACCESS_DENIED: NtStatus = NtStatus::new(0xC000_00CA);
// Informational severity rather than an error, so a server sending it succeeded
// and no caller meets it here; it is grouped for the same reason the reference
// groups it, which is that it says the object was already there.
const STATUS_OBJECT_NAME_EXISTS: NtStatus = NtStatus::new(0x4000_0000);
const STATUS_PENDING: NtStatus = NtStatus::new(0x0000_0103);
const STATUS_DEVICE_NOT_READY: NtStatus = NtStatus::new(0xC000_00A3);
const STATUS_NETWORK_BUSY: NtStatus = NtStatus::new(0xC000_00BF);
const STATUS_TOO_MANY_SESSIONS: NtStatus = NtStatus::new(0xC000_00CE);
const STATUS_RETRY: NtStatus = NtStatus::new(0xC000_022D);
