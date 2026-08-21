//! Share enumeration: RAP over `\PIPE\LANMAN`, and DCE/RPC `srvsvc` behind it.
//!
//! This is the one module in the crate with no oracle. smb-rs's `smb-rpc` is
//! NDR64-only and salvages nothing, the reference library's own decoder is
//! wrong in four of the ways listed below, and the corpus that stands behind it
//! is small. So the rules it works to are stated here rather than left to be
//! read off the code.
//!
//! **Both paths ask for information level 1**, which is what carries a share's
//! name, its kind and its comment — the three [`Share`] hands back. The
//! reference returns bare names and discards the other two.
//!
//! **RAP is tried first and `srvsvc` is the fallback, and the fall-through is
//! required rather than defensive.** Windows does not serve RAP at all: a
//! `NetShareEnum` with nothing wrong with it is answered
//! `STATUS_NOT_SUPPORTED`, and the same corpus enumerates four shares over
//! `srvsvc`. RAP's own `ERROR_MORE_DATA` falls through the same way: it says
//! the share list did not fit the RAP reply, and the port does not retry with a
//! larger receive buffer — the transaction ceiling may not permit one — it
//! treats RAP as unable to produce the list. The reference treats that as fatal
//! and enumerates nothing.
//!
//! **`NetrShareEnum`'s `ERROR_MORE_DATA` is a different thing entirely.**
//! `srvsvc` returns it together with a resume handle when the list does not fit,
//! and there is nothing further to fall through to — DCE/RPC is already the
//! fallback. So the port loops, re-issuing with the handle the previous reply
//! returned, until a reply comes back successful. **A list handed to the caller
//! with `ERROR_MORE_DATA` unresolved is an error and never a short answer.**
//!
//! Everything below the first RAP attempt is unreached against the container
//! this crate's CI runs, which answers RAP: the fixtures are what stands behind
//! it (see `fixtures/capture-nmpipe`, `fixtures/capture-win-nmpipe` and
//! `fixtures/srvsvc-synthesised`).

mod ndr;
mod pdu;
mod pipe;
mod rap;
mod srvsvc;

use tracing::debug;

use crate::connection::{Connection, Reply, Request};
use crate::error::{Error, Result};
use crate::status::NtStatus;
use crate::wire::header::command;
use crate::wire::transaction::{self, TransactionRequest};
use crate::wire::{Message, WireError};

use pipe::Pipe;

/// The pipe `srvsvc` is reached on, relative to the tree.
const SRVSVC_PIPE: &str = "\\srvsvc";

/// The most rounds one `NetrShareEnum` enumeration may take.
///
/// A liveness guard rather than a quantity derived from anything, in the same
/// register as the connection layer's cap of 64 fragments on one reassembly and
/// set to the same number. The no-progress guard below is what terminates an
/// ordinary misbehaving server; this is what bounds a server that pages
/// forever while adding an entry each round, and with it what bounds the
/// memory such a server can make this crate hold.
const MAX_ROUNDS: usize = 64;

/// What a share serves, and what the server says about it besides.
///
/// RAP spells the two flags in the top of a 16-bit field and `srvsvc` in the
/// top of a 32-bit one. Both are read into the same shape here, so a caller
/// cannot tell which path answered from the value it gets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareKind {
    /// What the share serves.
    pub service: ShareService,
    /// `STYPE_SPECIAL`: an administrative share, which is what the trailing `$`
    /// on `IPC$`, `ADMIN$` and `C$` conventionally marks.
    pub special: bool,
    /// `STYPE_TEMPORARY`: a share that does not survive the server restarting.
    pub temporary: bool,
}

/// What a share serves.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ShareService {
    /// A directory tree.
    Disk,
    /// A print queue.
    PrintQueue,
    /// A communication device.
    Device,
    /// Named pipes: `IPC$`, which is the share this module's own path runs on.
    Ipc,
    /// A type neither [MS-SRVS] nor [MS-RAP] names.
    ///
    /// [MS-SRVS]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-srvs/accf23b0-0f57-441c-9185-43041f1b0ee9
    /// [MS-RAP]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-rap/e711c777-c94d-413b-b19c-4c56bce9d8ea
    Other(u16),
}

impl ShareKind {
    /// `STYPE_SPECIAL` and `STYPE_TEMPORARY` as `srvsvc` spells them.
    const SRVSVC_SPECIAL: u32 = 0x8000_0000;
    const SRVSVC_TEMPORARY: u32 = 0x4000_0000;
    /// The same two as RAP spells them.
    const RAP_SPECIAL: u16 = 0x8000;
    const RAP_TEMPORARY: u16 = 0x4000;

    fn from_srvsvc(kind: u32) -> Self {
        Self {
            service: ShareService::from_code(
                (kind & !(Self::SRVSVC_SPECIAL | Self::SRVSVC_TEMPORARY)) as u16,
            ),
            special: kind & Self::SRVSVC_SPECIAL != 0,
            temporary: kind & Self::SRVSVC_TEMPORARY != 0,
        }
    }

    fn from_rap(kind: u16) -> Self {
        Self {
            service: ShareService::from_code(kind & !(Self::RAP_SPECIAL | Self::RAP_TEMPORARY)),
            special: kind & Self::RAP_SPECIAL != 0,
            temporary: kind & Self::RAP_TEMPORARY != 0,
        }
    }
}

impl ShareService {
    fn from_code(code: u16) -> Self {
        match code {
            0 => Self::Disk,
            1 => Self::PrintQueue,
            2 => Self::Device,
            3 => Self::Ipc,
            other => Self::Other(other),
        }
    }
}

/// One share a server offers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    /// The share's name, which is what a UNC path names it by.
    pub name: String,
    /// What it serves.
    pub kind: ShareKind,
    /// The server's description of it, empty where the server gives none.
    ///
    /// The reference library's public API discards this. It is kept because it
    /// is what a user browsing shares actually reads, and because discarding it
    /// would leave the decoder parsing a field it throws away.
    pub comment: String,
}

/// A tree connected to `IPC$`, which is where share enumeration runs.
///
/// This is what `tree.rs` hands `rpc/`: a connection, and the tree and user ids
/// of an `IPC$` tree connect it has already performed. Both paths need those
/// three and nothing else — RAP addresses `\PIPE\LANMAN` by name on a
/// transaction, and the DCE/RPC path opens `\srvsvc` on the same tree for
/// itself and closes it again.
#[derive(Debug, Clone)]
pub struct Ipc {
    connection: Connection,
    tid: u16,
    uid: u16,
}

impl Ipc {
    /// Names the tree the two paths run on.
    pub fn new(connection: Connection, tid: u16, uid: u16) -> Self {
        Self {
            connection,
            tid,
            uid,
        }
    }

    /// Enumerates the server's shares.
    ///
    /// `server` is the server component of the UNC path the caller named, with
    /// the port where the caller gave one; it is what the `srvsvc` request
    /// carries as its `ServerName` and is otherwise unused. RAP is tried first
    /// and DCE/RPC answers where it cannot.
    pub async fn list_shares(&self, server: &str) -> Result<Vec<Share>> {
        let first = match self.over_rap().await {
            Ok(shares) => {
                debug!(shares = shares.len(), "RAP enumerated the server's shares");
                return Ok(shares);
            }
            Err(error) => {
                debug!("RAP could not enumerate shares, falling through to srvsvc: {error}");
                error
            }
        };
        match self.over_srvsvc(server).await {
            Ok(shares) => {
                debug!(
                    shares = shares.len(),
                    "srvsvc enumerated the server's shares"
                );
                Ok(shares)
            }
            Err(second) => Err(Error::BothAttemptsFailed {
                operation: "share enumeration",
                first: Box::new(first),
                second: Box::new(second),
            }),
        }
    }

    /// One `SMB_COM_TRANSACTION` on `\PIPE\LANMAN`.
    async fn over_rap(&self) -> Result<Vec<Share>> {
        // The receive buffer and the transaction's own `MaxDataCount` are the
        // same number on purpose: the first is how large a reply the server may
        // build and the second is how large a reply it is allowed to return, and
        // a server told it may build a larger one than it may send would have
        // that reply refused a layer down as more than the request asked for.
        let request =
            TransactionRequest::rap(rap::request(transaction::MAX_DATA_COUNT), Vec::new());
        let reply = self.transaction(request, "RAP NetShareEnum").await?;
        if reply.status() != NtStatus::SUCCESS {
            return Err(refused(reply.status()));
        }
        let body = reply.transaction().ok_or_else(|| {
            Error::Protocol(Box::new(WireError::NoResponseBody {
                command: command::TRANSACTION,
                status: reply.status(),
            }))
        })?;
        rap::response(body.parameters(), body.data()).map_err(protocol)
    }

    /// A bind and however many `NetrShareEnum` rounds the server's answer takes.
    async fn over_srvsvc(&self, server: &str) -> Result<Vec<Share>> {
        let mut pipe = Pipe::open(self.connection.clone(), self.tid, self.uid, SRVSVC_PIPE).await?;
        let shares = self.enumerate(&mut pipe, server).await;
        pipe.close().await;
        shares
    }

    async fn enumerate(&self, pipe: &mut Pipe, server: &str) -> Result<Vec<Share>> {
        let bound = pipe
            .call(&pdu::bind(srvsvc::INTERFACE, srvsvc::INTERFACE_VERSION), 0)
            .await?;
        pdu::bind_ack(&bound).map_err(protocol)?;

        let mut shares: Vec<Share> = Vec::new();
        let mut resume = 0;
        for round in 0..MAX_ROUNDS {
            // The call id distinguishes this round's reply from the previous
            // round's, which is what lets the collector refuse a stale one.
            let call = round as u32 + 1;
            let answer = pipe
                .call(
                    &pdu::request(call, srvsvc::OPNUM, &srvsvc::request(server, resume)),
                    call,
                )
                .await?;
            let stub = pdu::Collector::response(&answer).map_err(protocol)?;
            let page = srvsvc::response(stub).map_err(protocol)?;

            let added = page.shares.len();
            shares.extend(page.shares);
            if !page.more {
                debug!(
                    rounds = round + 1,
                    total = page.total,
                    "the enumeration ended"
                );
                return Ok(shares);
            }
            // The no-progress guard: a reply that adds no entries and does not
            // end the enumeration is an error rather than another round. Without
            // it a server answering `ERROR_MORE_DATA` with an empty page loops
            // until the connection's own deadlines fire.
            if added == 0 {
                return Err(protocol(PagingError::NoProgress { resume }));
            }
            resume = page.resume;
        }
        Err(protocol(PagingError::TooManyRounds {
            rounds: MAX_ROUNDS,
            shares: shares.len(),
        }))
    }

    /// Issues one transaction on this tree.
    async fn transaction(&self, request: TransactionRequest, what: &'static str) -> Result<Reply> {
        request
            .check_limits(self.connection.negotiated().max_buffer_size)
            .map_err(|error| too_large(error, what))?;
        self.connection
            .request(Request::transaction(
                request.command,
                self.tid,
                self.uid,
                request.encode_body()?,
                request.max_parameter_count,
                request.max_data_count,
            ))
            .await
            .map_err(transport)
    }
}

/// What the `NetrShareEnum` paging loop can fail with.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
enum PagingError {
    /// A round that returned no entries and did not end the enumeration.
    #[error("NetrShareEnum returned no entries and more to come, at resume handle {resume}")]
    NoProgress {
        /// The handle that round was issued with.
        resume: u32,
    },

    /// More rounds than one enumeration may take.
    #[error("NetrShareEnum did not finish in {rounds} rounds, having returned {shares} shares")]
    TooManyRounds {
        /// The cap that was reached.
        rounds: usize,
        /// What had been collected by then.
        shares: usize,
    },
}

/// A decode failure, which a caller can do nothing about beyond reporting it.
fn protocol<E>(error: E) -> Error
where
    E: std::error::Error + Send + Sync + 'static,
{
    Error::Protocol(Box::new(error))
}

/// Re-parses a reply's message for a per-command decoder.
fn parse(reply: &Reply) -> Result<Message> {
    Ok(Message::parse(reply.message().to_vec())?)
}

/// A status a server refused an operation with.
// This mapping and `transport` below belong beside the error type once a second
// module reaches the connection layer; `rpc/` is the first one to exist.
fn refused(status: NtStatus) -> Error {
    match status {
        NtStatus::INSUFF_SERVER_RESOURCES => Error::TransactionRefused,
        NtStatus::NETWORK_NAME_DELETED => Error::TreeDisconnected,
        NtStatus::USER_SESSION_DELETED => Error::ConnectionLost {
            status: Some(status),
        },
        other => Error::Status(other),
    }
}

/// A transaction this crate built that will not fit one message.
fn too_large(error: WireError, request: &'static str) -> Error {
    match error {
        WireError::FieldTooLong {
            field: "transaction request",
            length,
            limit,
        } => Error::TransactionTooLarge {
            request,
            size: length,
            limit,
        },
        other => Error::Protocol(Box::new(other)),
    }
}

/// What a connection failure means to a caller.
fn transport(error: crate::connection::Error) -> Error {
    use crate::connection::Error as Transport;
    match error {
        Transport::Io(inner) => Error::Io(inner),
        Transport::Wire(inner) => Error::Protocol(Box::new(inner)),
        Transport::Timeout => Error::RequestTimeout,
        Transport::Reassembly(inner) => Error::Protocol(Box::new(inner)),
        Transport::SessionDeleted => Error::ConnectionLost {
            status: Some(NtStatus::USER_SESSION_DELETED),
        },
        // Everything else means the connection is gone and the next call must
        // re-dial. None of them carries a status.
        Transport::Lost
        | Transport::Unroutable { .. }
        | Transport::ChainedResponse(_)
        | Transport::Silent
        | Transport::RetirementBudget(_)
        | Transport::PoolExhausted => Error::ConnectionLost { status: None },
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::Path;

    use crate::wire::Message;

    /// Reads one committed fixture and parses it, its NetBIOS header stripped.
    pub(super) fn fixture(relative: &str) -> Message {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join(relative);
        let bytes = fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        Message::parse(bytes[4..].to_vec()).unwrap_or_else(|error| panic!("{relative}: {error}"))
    }

    /// The pipe payload of a `READ_ANDX` reply, which is where the fixtures on
    /// the write/read path keep their PDUs.
    pub(super) fn read_payload(relative: &str) -> Vec<u8> {
        crate::wire::io::ReadAndxResponse::decode(&fixture(relative))
            .unwrap_or_else(|error| panic!("{relative}: {error}"))
            .data
    }

    /// The pipe payload of an `SMB_COM_TRANSACTION` carrying a DCE/RPC PDU.
    pub(super) fn transaction_payload(relative: &str) -> Vec<u8> {
        let message = fixture(relative);
        if message.header().flags & 0x80 == 0 {
            crate::wire::transaction::TransactionRequest::decode(&message)
                .unwrap_or_else(|error| panic!("{relative}: {error}"))
                .data
        } else {
            crate::wire::transaction::TransactionResponse::decode(&message)
                .unwrap_or_else(|error| panic!("{relative}: {error}"))
                .data
        }
    }

    /// The stub of a DCE/RPC request or response PDU, its 16-byte header and
    /// 8-byte prologue removed.
    pub(super) fn stub(pdu: &[u8]) -> Vec<u8> {
        pdu[24..].to_vec()
    }
}
