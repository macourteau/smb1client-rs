//! The two named-pipe transports, and the fall-through between them.
//!
//! A DCE/RPC exchange on `\PIPE\srvsvc` is carried either by
//! `TRANS_TRANSACT_NMPIPE` — one `SMB_COM_TRANSACTION` carrying the request and
//! returning the response — or by writing the request to the pipe's file id
//! with `WRITE_ANDX` and reading the response back with `READ_ANDX`.
//!
//! **The write/read mode is a hedge with no tested server behind it.** All
//! three servers this crate's evidence campaign reached answer the transact
//! mode once the transaction `Name` is supplied: the Samba container, the
//! embedded device, and Windows, whose whole `srvsvc` exchange rides on
//! `SMB_COM_TRANSACTION`. It is kept because the two costs are not comparable —
//! a client carrying only the transact mode enumerates nothing against a server
//! that refuses one, while carrying the second mode costs code that never runs.
//!
//! **The fall-through triggers on any error from the transact attempt**, and
//! keeps that error, so a failure of both attempts still says why the first was
//! abandoned. Narrowing the trigger would rest on no evidence: the only
//! `STATUS_NOT_SUPPORTED` ever recorded here was earned by a client sending the
//! transaction with no `Name` at all.
//!
//! **Because the trigger is that wide, the pipe is reopened before the second
//! attempt.** The mode exists for a server that refuses the transaction, and a
//! refusal leaves the pipe as it was — but the same trigger fires on an error
//! raised once the response has begun arriving, and there the pipe still holds
//! the tail of what was abandoned. Writing the next request behind it is how one
//! clear failure becomes two confusing ones, the second of them a PDU carrying
//! no `PFC_FIRST_FRAG`.
//!
//! **The pipe-read loop owns `STATUS_BUFFER_OVERFLOW`.** In the write/read mode
//! it arrives on the `READ_ANDX`, which is not a transaction at all; in the
//! transact mode it arrives on a *completed* `SMB_COM_TRANSACTION` whose pipe
//! payload was truncated. Either way the remedy is another `READ_ANDX` on the
//! pipe until the response is whole, never more transaction fragments. The
//! reference library issues a single 64 KiB read and never loops.

use tracing::{debug, warn};

use crate::connection::{Connection, PROTOCOL_OVERHEAD, Request};
use crate::error::{Error, Result};
use crate::status::NtStatus;
use crate::wire::WireError;
use crate::wire::file::{CloseRequest, NtCreateAndxRequest, NtCreateAndxResponse};
use crate::wire::header::command;
use crate::wire::io::{ReadAndxRequest, ReadAndxResponse, WriteAndxRequest, WriteAndxResponse};
use crate::wire::transaction::TransactionRequest;

use super::pdu::{Answer, Collector};
use super::{protocol, too_large};

/// The most bytes one pipe read may ask for.
///
/// A pipe read has no large-read capability to raise it: `MaxCountHigh` is the
/// pipe's timeout on this command rather than the high half of a byte count, so
/// what a `READ_ANDX` on a pipe can ask for is sixteen bits wide whatever the
/// server advertised. This is the same flat 65,520 the reference uses for a
/// read without `CAP_LARGE_READX`, and for the same reason.
const MAX_PIPE_TRANSFER: u32 = 65_520;

/// `GENERIC_READ | GENERIC_WRITE`.
const DESIRED_ACCESS: u32 = 0xC000_0000;
/// `FILE_ATTRIBUTE_NORMAL`.
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
/// `FILE_SHARE_READ | FILE_SHARE_WRITE`.
const SHARE_ACCESS: u32 = 0x0000_0003;
/// `FILE_OPEN`: open the pipe that is there, and create nothing.
const FILE_OPEN: u32 = 0x0000_0001;
/// `SEC_IMPERSONATE`.
const IMPERSONATION: u32 = 0x0000_0002;
/// What a close asks the server to leave the last-write time alone.
const LEAVE_TIME_ALONE: u32 = 0xFFFF_FFFF;

/// An open named pipe on a tree, and the DCE/RPC exchanges carried over it.
#[derive(Debug)]
pub struct Pipe {
    connection: Connection,
    tid: u16,
    uid: u16,
    fid: u16,
    /// The pipe's byte cursor, advanced over everything written and read.
    ///
    /// A server ignores the offset on a pipe, which is a stream and not a file.
    /// It is tracked because the one capture of the write/read mode working
    /// carries an advancing cursor, and this is the transport with no tested
    /// server behind it: matching the only evidence there is costs one field.
    offset: u64,
    /// Whether the transact mode is still worth attempting.
    ///
    /// Cleared by the first error from it, and not re-tried afterwards on this
    /// pipe. A server that refused one transaction refuses the next, and the
    /// reference library's habit of re-attempting spends a round trip per call
    /// to rediscover it — visibly, in the capture of the exchange it takes.
    transact: bool,
    /// Why the transact mode was abandoned, kept so that a failure of both
    /// transports still says what the first one was.
    transact_failure: Option<Error>,
    /// The pipe's name, kept so the fall-through can reopen it.
    name: String,
}

impl Pipe {
    /// Opens a named pipe on an already-connected tree.
    ///
    /// `name` is the pipe's name relative to the tree, `\srvsvc` for share
    /// enumeration.
    pub async fn open(connection: Connection, tid: u16, uid: u16, name: &str) -> Result<Self> {
        let fid = Self::open_fid(&connection, tid, uid, name).await?;
        Ok(Self {
            connection,
            tid,
            uid,
            fid,
            offset: 0,
            transact: true,
            transact_failure: None,
            name: name.to_owned(),
        })
    }

    /// Opens the pipe and returns its file id, for both the first open and the
    /// reopen the fall-through makes.
    async fn open_fid(connection: &Connection, tid: u16, uid: u16, name: &str) -> Result<u16> {
        let request = NtCreateAndxRequest {
            flags: 0,
            root_directory_fid: 0,
            desired_access: DESIRED_ACCESS,
            allocation_size: 0,
            ext_file_attributes: FILE_ATTRIBUTE_NORMAL,
            share_access: SHARE_ACCESS,
            create_disposition: FILE_OPEN,
            create_options: 0,
            impersonation_level: IMPERSONATION,
            security_flags: 0,
            name: name.to_owned(),
        };
        let reply = connection
            .request(Request::new(
                command::NT_CREATE_ANDX,
                tid,
                uid,
                request.encode_body()?,
            ))
            .await?;
        if reply.status() != NtStatus::SUCCESS {
            return Err(Error::refused(reply.status()));
        }
        let opened = NtCreateAndxResponse::decode(reply.parsed())?;
        debug!(fid = opened.fid, name, "named pipe opened");
        Ok(opened.fid)
    }

    /// Closes the pipe and opens it again, so the transport that follows starts
    /// on a stream with nothing left on it.
    ///
    /// The fall-through below is written for a server that *refuses* the
    /// transact mode, and a refusal leaves the pipe as it was. An error raised
    /// after the response began arriving does not: the next request would go
    /// into a pipe still holding the tail of the abandoned one, and the read
    /// after it would land mid-stream on a PDU carrying no `PFC_FIRST_FRAG`.
    /// Reopening costs a round trip on the unlikely path and needs no claim
    /// about which errors leave the pipe clean — which is a claim this crate is
    /// in no position to make, the two modes being told apart by what the server
    /// did rather than by how far it got.
    async fn reopen(&mut self) -> Result<()> {
        Self::release(&self.connection, self.tid, self.uid, self.fid).await;
        self.fid = Self::open_fid(&self.connection, self.tid, self.uid, &self.name).await?;
        self.offset = 0;
        Ok(())
    }

    /// Releases the pipe.
    ///
    /// A close that fails is logged and not returned: the server releases every
    /// handle when the connection goes, so a failed close costs a handle until
    /// then and nothing the caller can act on.
    pub async fn close(self) {
        Self::release(&self.connection, self.tid, self.uid, self.fid).await;
    }

    /// Releases one file id, for both the close above and the reopen.
    async fn release(connection: &Connection, tid: u16, uid: u16, fid: u16) {
        let request = CloseRequest {
            fid,
            last_time_modified: LEAVE_TIME_ALONE,
        };
        let body = match request.encode_body() {
            Ok(body) => body,
            Err(error) => {
                warn!(fid, "encoding the pipe close failed: {error}");
                return;
            }
        };
        let reply = connection
            .request(Request::new(command::CLOSE, tid, uid, body))
            .await;
        match reply {
            Ok(reply) if reply.status() == NtStatus::SUCCESS => {}
            Ok(reply) => warn!(fid, "the server refused the pipe close: {}", reply.status()),
            Err(error) => warn!(fid, "the pipe close did not complete: {error}"),
        }
    }

    /// Writes one request PDU and collects the PDUs of its answer.
    pub async fn call(&mut self, request: &[u8], call_id: u32) -> Result<Answer> {
        if self.transact {
            let mut collector = Collector::new(call_id);
            match self.transact_call(request, &mut collector).await {
                Ok(()) => return collector.finish().map_err(protocol),
                Err(error) => {
                    warn!(
                        fid = self.fid,
                        "the pipe transact mode failed, falling through to write and read: {error}"
                    );
                    self.transact = false;
                    self.transact_failure = Some(error);
                    // The transact attempt may have got far enough to leave the
                    // tail of a response on the pipe, and writing the next
                    // request behind it is how one clear failure becomes two
                    // confusing ones. A reopen fails the call rather than
                    // proceeding on a stream whose state is unknown.
                    if let Err(error) = self.reopen().await {
                        return Err(self.both_failed(error));
                    }
                }
            }
        }

        let mut collector = Collector::new(call_id);
        match self.write_read_call(request, &mut collector).await {
            Ok(()) => collector.finish().map_err(protocol),
            Err(second) => Err(self.both_failed(second)),
        }
    }

    /// Reports a failure of the write/read mode beside whatever the transact
    /// mode failed with, where there was one.
    fn both_failed(&mut self, second: Error) -> Error {
        match self.transact_failure.take() {
            Some(first) => Error::BothAttemptsFailed {
                operation: "the DCE/RPC exchange on the named pipe",
                first: Box::new(first),
                second: Box::new(second),
            },
            None => second,
        }
    }

    /// One `SMB_COM_TRANSACTION` carrying the request and returning the
    /// response.
    async fn transact_call(&mut self, request: &[u8], collector: &mut Collector) -> Result<()> {
        let transaction = TransactionRequest::pipe_transact(self.fid, request.to_vec());
        let buffer = self.connection.negotiated().max_buffer_size;
        transaction
            .check_limits(buffer)
            .map_err(|error| too_large(error, "TRANS_TRANSACT_NMPIPE"))?;
        let reply = self
            .connection
            .request(Request::transaction(
                command::TRANSACTION,
                self.tid,
                self.uid,
                transaction.encode_body()?,
                transaction.max_parameter_count,
                transaction.max_data_count,
            ))
            .await?;
        // `STATUS_BUFFER_OVERFLOW` here is a *completed* transaction whose pipe
        // payload was truncated, delivered by the connection layer as the reply
        // it is. What it asks for is another pipe read, never more transaction
        // fragments.
        accept_pipe_status(reply.status())?;
        if let Some(body) = reply.transaction() {
            collector.feed(body.data()).map_err(protocol)?;
        }
        self.fill(collector).await
    }

    /// The request written to the pipe's file id, and the response read back.
    async fn write_read_call(&mut self, request: &[u8], collector: &mut Collector) -> Result<()> {
        self.write_all(request).await?;
        self.fill(collector).await
    }

    /// Writes every byte of the request to the pipe.
    ///
    /// A write acknowledged short is re-issued from the first unacknowledged
    /// byte, and one acknowledged with zero bytes is an error rather than
    /// another attempt — the no-progress rule the crate's other loops carry.
    async fn write_all(&mut self, request: &[u8]) -> Result<()> {
        let chunk = self.transfer_size() as usize;
        let mut written = 0;
        while written < request.len() {
            let end = (written + chunk).min(request.len());
            let body = WriteAndxRequest {
                fid: self.fid,
                offset: self.offset,
                write_mode: 0,
                remaining: 0,
                data: request[written..end].to_vec(),
            }
            .encode_body()?;
            let reply = self
                .connection
                .request(Request::new(command::WRITE_ANDX, self.tid, self.uid, body))
                .await?;
            accept_pipe_status(reply.status())?;
            let acknowledged = WriteAndxResponse::decode(reply.parsed())?.count as usize;
            if acknowledged == 0 {
                return Err(Error::Protocol(Box::new(WireError::Truncated {
                    part: "the pipe write acknowledgement",
                    declared: end - written,
                    length: 0,
                })));
            }
            let progress = acknowledged.min(end - written);
            written += progress;
            self.offset += progress as u64;
        }
        Ok(())
    }

    /// Reads the pipe until the answer is whole.
    ///
    /// What decides that is `PFC_LAST_FRAG` on a PDU and nothing else: a read
    /// answered with fewer bytes than it asked for says nothing about whether
    /// the server has finished answering, and a read answered
    /// `STATUS_BUFFER_OVERFLOW` says the opposite. A read that returns no bytes
    /// at all is the loop's no-progress guard, and it fails the call rather
    /// than handing back a truncated answer.
    async fn fill(&mut self, collector: &mut Collector) -> Result<()> {
        while !collector.complete() {
            let body = ReadAndxRequest {
                fid: self.fid,
                offset: self.offset,
                max_count: self.transfer_size(),
                min_count: 0,
                remaining: 0,
            }
            .encode_body()?;
            let reply = self
                .connection
                .request(Request::new(command::READ_ANDX, self.tid, self.uid, body))
                .await?;
            accept_pipe_status(reply.status())?;
            let data = ReadAndxResponse::decode(reply.parsed())?.data;
            if data.is_empty() {
                // The no-progress guard. The pipe has nothing more to give and
                // no PDU has closed the answer, so what arrived is a fragment
                // of a reply rather than a short one: `Collector::finish` fails
                // the call and names the flag that never came.
                break;
            }
            self.offset += data.len() as u64;
            collector.feed(&data).map_err(protocol)?;
        }
        Ok(())
    }

    /// The most bytes one read or write on this pipe moves.
    fn transfer_size(&self) -> u32 {
        (self.connection
            .negotiated()
            .max_buffer_size
            // Plain arithmetic, and the crate's one overhead constant: a second
            // copy of either would drift from this one.
            - PROTOCOL_OVERHEAD)
            .min(MAX_PIPE_TRANSFER)
    }
}

/// The two statuses a pipe operation may carry and still be answering.
///
/// `STATUS_BUFFER_OVERFLOW` is not in the `0xC0000000` class and so reads to the
/// reference library as success. It says the response did not fit the request
/// that asked for it, which is the read loop's business and not a failure.
fn accept_pipe_status(status: NtStatus) -> Result<()> {
    if status == NtStatus::SUCCESS || status == NtStatus::BUFFER_OVERFLOW {
        return Ok(());
    }
    Err(Error::refused(status))
}
