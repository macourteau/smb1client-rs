//! Share enumeration, driven over the connection's test seam against a
//! scripted server.
//!
//! Two of the things this suite covers **have no fixture and can get none**.
//! Every committed `srvsvc` response is a single PDU carrying
//! `PFC_FIRST|PFC_LAST`, and every one is a complete enumeration — `TotalEntries`
//! equal to `EntriesRead`, the resume handle back at zero and the return value
//! `WERR_OK`. So the multi-PDU assembly loop and the `NetrShareEnum` paging
//! loop are exercised by hand-built streams here, and each of those tests says
//! what a plausible wrong implementation returns where the correct one does
//! not. They are the parts a server with many shares reaches first, and where a
//! port without them truncates silently.
//!
//! What *is* pinned by captured bytes is everything else, and it is pinned in
//! the unit tests beside the code: the bind and request PDUs byte for byte
//! against five corpora, the four shares Windows returns and the two the
//! container returns with their kinds and comments, and the one answered RAP
//! reply in the corpus. The frames replayed below carry those same payloads.

use std::fs;
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::timeout;

use smb1client::connection::{Connection, Negotiated, Timeouts, transport};
use smb1client::rpc::{Ipc, Share, ShareService};
use smb1client::{Error, NtStatus};

const HEADER_LEN: usize = 32;
const TID: u16 = 0x0E0B;
const UID: u16 = 0x987C;
const FID: u16 = 0xE7EA;
const SERVER: &str = "127.0.0.1:10451";

const CLOSE: u8 = 0x04;
const TRANSACTION: u8 = 0x25;
const READ_ANDX: u8 = 0x2E;
const WRITE_ANDX: u8 = 0x2F;
const NT_CREATE_ANDX: u8 = 0xA2;

/// How long a test waits before concluding nothing more is coming.
const SETTLE: Duration = Duration::from_millis(50);

// ---------------------------------------------------------------------------
// The scripted server.
// ---------------------------------------------------------------------------

struct Peer {
    stream: DuplexStream,
}

impl Peer {
    async fn try_frame(&mut self) -> Option<Vec<u8>> {
        let mut header = [0u8; 4];
        match self.stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return None,
            Err(error) => panic!("reading a NetBIOS header: {error}"),
        }
        let length = (usize::from(header[1] & 0x01) << 16)
            | usize::from(u16::from_be_bytes([header[2], header[3]]));
        let mut message = vec![0; length];
        self.stream
            .read_exact(&mut message)
            .await
            .expect("a whole frame");
        Some(message)
    }

    /// The next request, asserted to be the command expected of it.
    async fn request(&mut self, command: u8) -> Vec<u8> {
        let frame = timeout(SETTLE, self.try_frame())
            .await
            .unwrap_or_else(|_| panic!("no request arrived where {command:#04x} was expected"))
            .expect("a request, not the end of the stream");
        assert_eq!(
            frame[4], command,
            "expected command {command:#04x}, got {:#04x}",
            frame[4]
        );
        assert_eq!(u16::from_le_bytes([frame[24], frame[25]]), TID);
        assert_eq!(u16::from_le_bytes([frame[28], frame[29]]), UID);
        frame
    }

    /// Whether the client has stopped asking. The actor ending — which is what
    /// dropping the last handle does — reads as end of stream here, not as a
    /// request.
    async fn quiet(&mut self) -> bool {
        matches!(timeout(SETTLE, self.try_frame()).await, Err(_) | Ok(None))
    }

    async fn send(&mut self, message: &[u8]) {
        let length = message.len();
        let mut out = vec![
            0x00,
            ((length >> 16) & 0x01) as u8,
            ((length >> 8) & 0xFF) as u8,
            (length & 0xFF) as u8,
        ];
        out.extend_from_slice(message);
        self.stream
            .write_all(&out)
            .await
            .expect("the client is reading");
    }
}

fn pair() -> (Ipc, Peer) {
    let (client, server) = tokio::io::duplex(256 * 1024);
    let connection: Connection = transport::spawn(
        client,
        Negotiated {
            max_mpx_count: 50,
            max_buffer_size: 16_644,
            capabilities: 0,
        },
        Timeouts::default(),
    );
    (Ipc::new(connection, TID, UID), Peer { stream: server })
}

// ---------------------------------------------------------------------------
// Reply shapes, hand-built.
// ---------------------------------------------------------------------------

/// A reply header echoing the request's command, tree, user and multiplex ids.
fn reply(request: &[u8], status: NtStatus) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(b"\xffSMB");
    header.push(request[4]);
    header.extend_from_slice(&status.code().to_le_bytes());
    header.push(0x98);
    header.extend_from_slice(&0xC803u16.to_le_bytes());
    header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&[0u8; 8]);
    header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&request[24..32]);
    header
}

fn body(words: &[u8], byte_area: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.push((words.len() / 2) as u8);
    out.extend_from_slice(words);
    out.extend_from_slice(&(byte_area.len() as u16).to_le_bytes());
    out.extend_from_slice(byte_area);
    out
}

/// The shape SMB1 usually answers a failed command with.
fn refusal(request: &[u8], status: NtStatus) -> Vec<u8> {
    let mut message = reply(request, status);
    message.extend_from_slice(&body(&[], &[]));
    message
}

fn nt_create_reply(request: &[u8]) -> Vec<u8> {
    let mut words = vec![0xFF, 0x00, 0x00, 0x00, 0x00];
    words.extend_from_slice(&FID.to_le_bytes());
    words.extend_from_slice(&1u32.to_le_bytes());
    words.extend_from_slice(&[0u8; 32]);
    words.extend_from_slice(&0x80u32.to_le_bytes());
    words.extend_from_slice(&[0u8; 16]);
    // ResourceType 2 is a named pipe; NMPipeStatus and Directory follow.
    words.extend_from_slice(&2u16.to_le_bytes());
    words.extend_from_slice(&0u16.to_le_bytes());
    words.push(0);
    assert_eq!(words.len(), 68);
    let mut message = reply(request, NtStatus::SUCCESS);
    message.extend_from_slice(&body(&words, &[]));
    message
}

fn transaction_reply(request: &[u8], status: NtStatus, parameters: &[u8], data: &[u8]) -> Vec<u8> {
    let mut area = Vec::new();
    let mut at = HEADER_LEN + 1 + 20 + 2;
    let parameter_offset = if parameters.is_empty() {
        0
    } else {
        let offset = at;
        area.extend_from_slice(parameters);
        at += parameters.len();
        offset
    };
    while !at.is_multiple_of(2) {
        area.push(0);
        at += 1;
    }
    let data_offset = at;
    area.extend_from_slice(data);

    let mut words = Vec::new();
    for word in [
        parameters.len() as u16,
        data.len() as u16,
        0,
        parameters.len() as u16,
        parameter_offset as u16,
        0,
        data.len() as u16,
        data_offset as u16,
        0,
    ] {
        words.extend_from_slice(&word.to_le_bytes());
    }
    words.extend_from_slice(&[0, 0]);
    let mut message = reply(request, status);
    message.extend_from_slice(&body(&words, &area));
    message
}

fn write_reply(request: &[u8], count: u16) -> Vec<u8> {
    let mut words = vec![0xFF, 0x00, 0x00, 0x00];
    words.extend_from_slice(&count.to_le_bytes());
    words.extend_from_slice(&[0u8; 6]);
    let mut message = reply(request, NtStatus::SUCCESS);
    message.extend_from_slice(&body(&words, &[]));
    message
}

fn read_reply(request: &[u8], status: NtStatus, data: &[u8]) -> Vec<u8> {
    // One pad byte between `ByteCount` and the payload, which is what puts
    // `DataOffset` at 60 rather than 59.
    let data_offset = HEADER_LEN + 1 + 24 + 2 + 1;
    let mut words = vec![0xFF, 0x00, 0x00, 0x00];
    words.extend_from_slice(&0u16.to_le_bytes());
    words.extend_from_slice(&0u16.to_le_bytes());
    words.extend_from_slice(&0u16.to_le_bytes());
    words.extend_from_slice(&(data.len() as u16).to_le_bytes());
    words.extend_from_slice(&(data_offset as u16).to_le_bytes());
    words.extend_from_slice(&((data.len() >> 16) as u16).to_le_bytes());
    words.extend_from_slice(&[0u8; 8]);
    assert_eq!(words.len(), 24);
    let mut area = vec![0u8];
    area.extend_from_slice(data);
    let mut message = reply(request, status);
    message.extend_from_slice(&body(&words, &area));
    message
}

// ---------------------------------------------------------------------------
// Reading the corpus.
// ---------------------------------------------------------------------------

fn fixture(relative: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(relative);
    let bytes = fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    bytes[4..].to_vec()
}

/// How many bytes a `WRITE_ANDX` request carried: `DataLength` sits at word
/// offset 20.
fn written_bytes(request: &[u8]) -> u16 {
    u16::from_le_bytes([request[53], request[54]])
}

/// A block a captured message declared at an absolute offset.
fn block(message: &[u8], offset_at: usize, count_at: usize) -> Vec<u8> {
    let words = &message[33..];
    let offset = usize::from(u16::from_le_bytes([words[offset_at], words[offset_at + 1]]));
    let count = usize::from(u16::from_le_bytes([words[count_at], words[count_at + 1]]));
    message[offset..offset + count].to_vec()
}

/// The parameter and data blocks of a captured transaction reply.
///
/// A reply's `ParameterOffset` sits at word offset 8 and its `DataOffset` at
/// 14, with the two counts at 6 and 12.
fn captured_transaction(relative: &str) -> (Vec<u8>, Vec<u8>) {
    (
        block(&fixture(relative), 8, 6),
        block(&fixture(relative), 14, 12),
    )
}

/// The data block of a transaction *request*, whose word layout is not the
/// reply's: `DataOffset` sits at word offset 24 and `DataCount` at 22.
fn request_data(message: &[u8]) -> Vec<u8> {
    block(message, 24, 22)
}

/// The payload of a captured `READ_ANDX` reply, whose `DataOffset` sits at word
/// offset 12 and whose `DataLength` sits at 10.
fn captured_read(relative: &str) -> Vec<u8> {
    block(&fixture(relative), 12, 10)
}

// ---------------------------------------------------------------------------
// Stub and PDU construction, for the cases the corpus cannot hold.
// ---------------------------------------------------------------------------

fn ndr_string(out: &mut Vec<u8>, text: &str) {
    let units: Vec<u16> = text.encode_utf16().chain([0]).collect();
    for count in [units.len() as u32, 0, units.len() as u32] {
        out.extend_from_slice(&count.to_le_bytes());
    }
    for unit in units {
        out.extend_from_slice(&unit.to_le_bytes());
    }
    out.resize(out.len().next_multiple_of(4), 0);
}

/// A `NetrShareEnum` reply stub, built the way a server does.
fn enum_stub(shares: &[(&str, u32, &str)], total: u32, resume: u32, code: u32) -> Vec<u8> {
    let mut out = Vec::new();
    let mut referent = 0x0002_0014u32;
    for value in [
        1,
        1,
        0x0002_000C,
        shares.len() as u32,
        0x0002_0010,
        shares.len() as u32,
    ] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    for (_, kind, _) in shares {
        out.extend_from_slice(&referent.to_le_bytes());
        out.extend_from_slice(&kind.to_le_bytes());
        out.extend_from_slice(&(referent + 4).to_le_bytes());
        referent += 8;
    }
    for (name, _, comment) in shares {
        ndr_string(&mut out, name);
        ndr_string(&mut out, comment);
    }
    for value in [total, referent, resume, code] {
        out.extend_from_slice(&value.to_le_bytes());
    }
    out
}

const PFC_FIRST: u8 = 0x01;
const PFC_LAST: u8 = 0x02;

fn response_pdu(call_id: u32, flags: u8, stub: &[u8]) -> Vec<u8> {
    let length = (16 + 8 + stub.len()) as u16;
    let mut out = vec![5, 0, 0x02, flags, 0x10, 0, 0, 0];
    out.extend_from_slice(&length.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out.extend_from_slice(&call_id.to_le_bytes());
    out.extend_from_slice(&(stub.len() as u32).to_le_bytes());
    out.extend_from_slice(&[0, 0, 0, 0]);
    out.extend_from_slice(stub);
    out
}

/// The `bind_ack` every corpus carries, replayed.
fn bind_ack() -> Vec<u8> {
    captured_transaction("capture-nmpipe/0012-s2c-cmd25.bin").1
}

/// A RAP reply's parameter block.
fn rap_parameters(status: u16, converter: u16, returned: u16, available: u16) -> Vec<u8> {
    let mut out = Vec::new();
    for word in [status, converter, returned, available] {
        out.extend_from_slice(&word.to_le_bytes());
    }
    out
}

fn names(shares: &[Share]) -> Vec<&str> {
    shares.iter().map(|share| share.name.as_str()).collect()
}

// ===========================================================================
// RAP answers, and nothing else is asked.
// ===========================================================================

/// The container answers RAP, so share enumeration stops there and **neither
/// DCE/RPC transport runs at all**. This is the shape the crate's own CI meets,
/// and the reason everything below it is fixture-covered rather than live.
///
/// The bytes replayed are `capture-rap/0010-s2c-cmd25.bin`, the one answered
/// RAP reply in the corpus.
#[tokio::test]
async fn rap_answers_and_neither_dce_rpc_transport_runs() {
    let (ipc, mut peer) = pair();
    let enumeration = tokio::spawn(async move { ipc.list_shares(SERVER).await });

    let request = peer.request(TRANSACTION).await;
    // The RAP shape: no setup words, and `\PIPE\LANMAN` in UTF-16 in the byte
    // area, which is what a server answers and what the reference mis-spells.
    assert_eq!(request[32], 14, "a RAP request carries no setup words");
    let name: Vec<u16> = request[64..64 + 24]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    assert_eq!(String::from_utf16(&name).unwrap(), "\\PIPE\\LANMAN");

    let (parameters, data) = captured_transaction("capture-rap/0010-s2c-cmd25.bin");
    peer.send(&transaction_reply(
        &request,
        NtStatus::SUCCESS,
        &parameters,
        &data,
    ))
    .await;

    let shares = enumeration.await.unwrap().unwrap();
    assert_eq!(names(&shares), ["testshare", "IPC$"]);
    assert_eq!(shares[1].comment, "IPC Service (Samba 4.23.8)");
    assert!(
        peer.quiet().await,
        "the client asked for more after RAP answered"
    );
}

// ===========================================================================
// The fall-through to DCE/RPC.
// ===========================================================================

/// Drives the whole `srvsvc` exchange over the transact mode, answering the
/// `NetrShareEnum` with whatever stubs the caller supplies — one PDU per round.
async fn srvsvc_over_transact(peer: &mut Peer, rounds: &[Vec<u8>]) {
    let create = peer.request(NT_CREATE_ANDX).await;
    peer.send(&nt_create_reply(&create)).await;

    let bind = peer.request(TRANSACTION).await;
    // Every transact-mode request carries `\PIPE\` and the subcommand and file
    // id in its setup words. The reference sends no name at all.
    assert_eq!(bind[32], 16, "a transact request carries two setup words");
    assert_eq!(u16::from_le_bytes([bind[61], bind[62]]), 0x0026);
    assert_eq!(u16::from_le_bytes([bind[63], bind[64]]), FID);
    let name: Vec<u16> = bind[68..68 + 12]
        .chunks_exact(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    assert_eq!(String::from_utf16(&name).unwrap(), "\\PIPE\\");
    peer.send(&transaction_reply(
        &bind,
        NtStatus::SUCCESS,
        &[],
        &bind_ack(),
    ))
    .await;

    for (round, stub) in rounds.iter().enumerate() {
        let call = peer.request(TRANSACTION).await;
        let pdu = response_pdu(round as u32 + 1, PFC_FIRST | PFC_LAST, stub);
        peer.send(&transaction_reply(&call, NtStatus::SUCCESS, &[], &pdu))
            .await;
    }

    let close = peer.request(CLOSE).await;
    peer.send(&refusal(&close, NtStatus::SUCCESS)).await;
}

/// Windows answers a well-formed `NetShareEnum` with `STATUS_NOT_SUPPORTED`,
/// which is what makes this fall-through required rather than defensive: the
/// same corpus enumerates four shares over `srvsvc`.
#[tokio::test]
async fn rap_refused_not_supported_falls_through_to_srvsvc() {
    let (ipc, mut peer) = pair();
    let enumeration = tokio::spawn(async move { ipc.list_shares("127.0.0.1").await });

    let rap = peer.request(TRANSACTION).await;
    peer.send(&refusal(&rap, NtStatus::NOT_SUPPORTED)).await;

    let stub = block(&fixture("capture-win-nmpipe/0014-s2c-cmd25.bin"), 14, 12)[24..].to_vec();
    srvsvc_over_transact(&mut peer, &[stub]).await;

    let shares = enumeration.await.unwrap().unwrap();
    assert_eq!(names(&shares), ["ADMIN$", "C$", "IPC$", "testshare"]);
    assert_eq!(shares[0].comment, "Remote Admin");
    assert!(shares[2].kind.special);
    assert_eq!(shares[2].kind.service, ShareService::Ipc);
}

/// **RAP's `ERROR_MORE_DATA` is a fall-through, not a failure.** It says the
/// share list did not fit the RAP reply, and the port treats RAP as unable to
/// produce the list rather than retrying with a larger receive buffer. The
/// reference library treats it as fatal and enumerates nothing — which is what
/// this test would catch: it would return an error where four shares are
/// available over the path beside it.
#[tokio::test]
async fn rap_more_data_falls_through_rather_than_enumerating_nothing() {
    let (ipc, mut peer) = pair();
    let enumeration = tokio::spawn(async move { ipc.list_shares("127.0.0.1").await });

    let rap = peer.request(TRANSACTION).await;
    // `ERROR_MORE_DATA`: one entry returned of nine available.
    let mut entry = vec![0u8; 20];
    entry[..5].copy_from_slice(b"first");
    peer.send(&transaction_reply(
        &rap,
        NtStatus::SUCCESS,
        &rap_parameters(234, 0, 1, 9),
        &entry,
    ))
    .await;

    let stub = block(&fixture("capture-win-nmpipe/0014-s2c-cmd25.bin"), 14, 12)[24..].to_vec();
    srvsvc_over_transact(&mut peer, &[stub]).await;

    let shares = enumeration.await.unwrap().unwrap();
    assert_eq!(names(&shares), ["ADMIN$", "C$", "IPC$", "testshare"]);
}

/// A RAP reply that succeeds while saying it had more entries than it returned
/// is the silent-truncation shape, and it falls through rather than being
/// handed back as a whole list.
#[tokio::test]
async fn a_rap_reply_short_of_its_own_available_count_falls_through() {
    let (ipc, mut peer) = pair();
    let enumeration = tokio::spawn(async move { ipc.list_shares("127.0.0.1").await });

    let rap = peer.request(TRANSACTION).await;
    let mut entry = vec![0u8; 20];
    entry[..5].copy_from_slice(b"first");
    peer.send(&transaction_reply(
        &rap,
        NtStatus::SUCCESS,
        &rap_parameters(0, 0, 1, 4),
        &entry,
    ))
    .await;

    srvsvc_over_transact(&mut peer, &[enum_stub(&[("only", 0, "")], 1, 0, 0)]).await;
    let shares = enumeration.await.unwrap().unwrap();
    assert_eq!(names(&shares), ["only"]);
}

// ===========================================================================
// The transact-to-write/read fall-through.
// ===========================================================================

/// The transact fall-through, driven by the exchange
/// `fixtures/capture-trans/` captured: the container refusing every
/// `SMB_COM_TRANSACTION` and answering the same calls over
/// `WRITE_ANDX`/`READ_ANDX`.
///
/// The fall-through is recorded on the pipe rather than re-attempted per call,
/// so the `NetrShareEnum` goes straight to the write/read mode — one round trip
/// fewer than the reference spends, which re-tries the transact mode and is
/// refused again.
#[tokio::test]
async fn a_refused_transact_falls_through_to_write_and_read() {
    let (ipc, mut peer) = pair();
    let enumeration = tokio::spawn(async move { ipc.list_shares(SERVER).await });

    let rap = peer.request(TRANSACTION).await;
    peer.send(&refusal(&rap, NtStatus::NOT_SUPPORTED)).await;

    let create = peer.request(NT_CREATE_ANDX).await;
    peer.send(&nt_create_reply(&create)).await;

    // The bind, refused on the transaction and accepted on the write.
    let attempt = peer.request(TRANSACTION).await;
    peer.send(&refusal(&attempt, NtStatus::NOT_SUPPORTED)).await;

    let write = peer.request(WRITE_ANDX).await;
    peer.send(&write_reply(&write, written_bytes(&write))).await;
    let read = peer.request(READ_ANDX).await;
    peer.send(&read_reply(&read, NtStatus::SUCCESS, &bind_ack()))
        .await;

    // The call itself. No second transaction is attempted.
    let write = peer.request(WRITE_ANDX).await;
    peer.send(&write_reply(&write, written_bytes(&write))).await;
    let read = peer.request(READ_ANDX).await;
    // A pipe read is sixteen bits wide however large the negotiated buffer:
    // `MaxCountHigh` is the pipe's timeout on this command and not the high
    // half of a byte count.
    let asked = u16::from_le_bytes([read[43], read[44]]);
    assert_eq!(
        u32::from_le_bytes([read[47], read[48], read[49], read[50]]),
        0,
        "a pipe read must leave MaxCountHigh alone"
    );
    assert_eq!(asked, 15_620, "16,644 negotiated, less the 1,024 reserved");
    peer.send(&read_reply(
        &read,
        NtStatus::SUCCESS,
        &captured_read("capture-trans/0028-s2c-cmd2e.bin"),
    ))
    .await;

    let close = peer.request(CLOSE).await;
    peer.send(&refusal(&close, NtStatus::SUCCESS)).await;

    let shares = enumeration.await.unwrap().unwrap();
    assert_eq!(names(&shares), ["testshare", "IPC$"]);
    assert_eq!(shares[1].comment, "IPC Service (Samba 4.23.8)");
}

// ===========================================================================
// The pipe-read loop, which owns STATUS_BUFFER_OVERFLOW.
// ===========================================================================

/// **No fixture covers this and none can.** A `NetrShareEnum` answer split
/// across two PDUs, delivered over three SMB operations: a completed
/// `SMB_COM_TRANSACTION` answered `STATUS_BUFFER_OVERFLOW`, and two
/// `READ_ANDX`s after it.
///
/// What a plausible wrong implementation does here, and what this catches:
///
/// - treating `STATUS_BUFFER_OVERFLOW` as an error — the reference classifies
///   it as success and so never meets it, but a port that read the `0x80000005`
///   as a failure would return one here;
/// - treating a completed transaction answered `STATUS_BUFFER_OVERFLOW` as a
///   fragment to keep reassembling, which waits for messages the server will
///   never send until the request lapses;
/// - issuing one read and not looping, as the reference does, which returns the
///   first PDU's stub — three shares' worth of a five-share reply, and it does
///   not decode at all;
/// - parsing the first PDU rather than the assembled stub, which is the same
///   truncation one layer up.
#[tokio::test]
async fn the_read_loop_collects_a_response_that_did_not_fit_one_reply() {
    let (ipc, mut peer) = pair();
    let enumeration = tokio::spawn(async move { ipc.list_shares(SERVER).await });

    let rap = peer.request(TRANSACTION).await;
    peer.send(&refusal(&rap, NtStatus::NOT_SUPPORTED)).await;
    let create = peer.request(NT_CREATE_ANDX).await;
    peer.send(&nt_create_reply(&create)).await;
    let bind = peer.request(TRANSACTION).await;
    peer.send(&transaction_reply(
        &bind,
        NtStatus::SUCCESS,
        &[],
        &bind_ack(),
    ))
    .await;

    let stub = enum_stub(
        &[
            ("alpha", 0, "the first"),
            ("beta", 0, "the second"),
            ("gamma", 0, "the third"),
            ("delta", 0, "the fourth"),
            ("IPC$", 0x8000_0003, "the pipes"),
        ],
        5,
        0,
        0,
    );
    let split = 96;
    let first = response_pdu(1, PFC_FIRST, &stub[..split]);
    let second = response_pdu(1, PFC_LAST, &stub[split..]);

    // The transaction completes, and says its pipe payload was truncated.
    let call = peer.request(TRANSACTION).await;
    peer.send(&transaction_reply(
        &call,
        NtStatus::BUFFER_OVERFLOW,
        &[],
        &first[..40],
    ))
    .await;

    // The remedy is a pipe read, and then another, until a PDU closes the
    // answer. Neither read is a transaction fragment.
    let read = peer.request(READ_ANDX).await;
    peer.send(&read_reply(&read, NtStatus::BUFFER_OVERFLOW, &first[40..]))
        .await;
    let read = peer.request(READ_ANDX).await;
    peer.send(&read_reply(&read, NtStatus::SUCCESS, &second))
        .await;

    let close = peer.request(CLOSE).await;
    peer.send(&refusal(&close, NtStatus::SUCCESS)).await;

    let shares = enumeration.await.unwrap().unwrap();
    assert_eq!(names(&shares), ["alpha", "beta", "gamma", "delta", "IPC$"]);
    assert_eq!(shares[4].comment, "the pipes");
    assert!(shares[4].kind.special);
}

/// A stream that ends before a PDU carries `PFC_LAST_FRAG` is an error, not a
/// short result. A port that returned what had arrived would hand back two
/// shares of five and report the enumeration complete.
#[tokio::test]
async fn a_response_that_never_ends_fails_rather_than_truncating() {
    let (ipc, mut peer) = pair();
    let enumeration = tokio::spawn(async move { ipc.list_shares(SERVER).await });

    let rap = peer.request(TRANSACTION).await;
    peer.send(&refusal(&rap, NtStatus::NOT_SUPPORTED)).await;
    let create = peer.request(NT_CREATE_ANDX).await;
    peer.send(&nt_create_reply(&create)).await;
    let bind = peer.request(TRANSACTION).await;
    peer.send(&transaction_reply(
        &bind,
        NtStatus::SUCCESS,
        &[],
        &bind_ack(),
    ))
    .await;

    // A complete, decodable two-share stub — but the PDU carrying it never
    // closes the answer, so the server has more to send and stops.
    let stub = enum_stub(&[("alpha", 0, ""), ("beta", 0, "")], 5, 0, 0);
    let call = peer.request(TRANSACTION).await;
    peer.send(&transaction_reply(
        &call,
        NtStatus::BUFFER_OVERFLOW,
        &[],
        &response_pdu(1, PFC_FIRST, &stub),
    ))
    .await;
    let read = peer.request(READ_ANDX).await;
    peer.send(&read_reply(&read, NtStatus::SUCCESS, &[])).await;

    let close = peer.request(CLOSE).await;
    peer.send(&refusal(&close, NtStatus::SUCCESS)).await;

    let error = enumeration.await.unwrap().unwrap_err();
    let message = error.to_string();
    assert!(
        message.contains("PFC_LAST_FRAG"),
        "the failure should name the missing flag: {message}"
    );
}

// ===========================================================================
// NetrShareEnum paging.
// ===========================================================================

/// **No fixture covers this and none can.** Every committed `srvsvc` response
/// is a complete enumeration.
///
/// `srvsvc` returns `ERROR_MORE_DATA` *with a resume handle* when the list does
/// not fit, and there is nothing further to fall through to. So the port loops,
/// re-issuing with the handle the previous reply returned. What this catches is
/// a port that returns the first page: it would hand back two shares of five,
/// silently, and report success.
#[tokio::test]
async fn netr_share_enum_pages_until_a_reply_comes_back_successful() {
    let (ipc, mut peer) = pair();
    let enumeration = tokio::spawn(async move { ipc.list_shares(SERVER).await });

    let rap = peer.request(TRANSACTION).await;
    peer.send(&refusal(&rap, NtStatus::NOT_SUPPORTED)).await;
    let create = peer.request(NT_CREATE_ANDX).await;
    peer.send(&nt_create_reply(&create)).await;
    let bind = peer.request(TRANSACTION).await;
    peer.send(&transaction_reply(
        &bind,
        NtStatus::SUCCESS,
        &[],
        &bind_ack(),
    ))
    .await;

    // Round one: two shares, more to come, resume handle 2.
    let first = peer.request(TRANSACTION).await;
    let stub = request_data(&first);
    assert_eq!(
        &stub[stub.len() - 4..],
        &0u32.to_le_bytes(),
        "the first round carries a resume handle of zero"
    );
    let page = enum_stub(&[("alpha", 0, "one"), ("beta", 0, "two")], 5, 2, 234);
    peer.send(&transaction_reply(
        &first,
        NtStatus::SUCCESS,
        &[],
        &response_pdu(1, PFC_FIRST | PFC_LAST, &page),
    ))
    .await;

    // Round two: the rest, and the handle the first round returned.
    let second = peer.request(TRANSACTION).await;
    let stub = request_data(&second);
    assert_eq!(
        &stub[stub.len() - 4..],
        &2u32.to_le_bytes(),
        "the second round carries the handle the first returned"
    );
    let page = enum_stub(
        &[("gamma", 0, "three"), ("delta", 0, "four"), ("IPC$", 3, "")],
        5,
        0,
        0,
    );
    peer.send(&transaction_reply(
        &second,
        NtStatus::SUCCESS,
        &[],
        &response_pdu(2, PFC_FIRST | PFC_LAST, &page),
    ))
    .await;

    let close = peer.request(CLOSE).await;
    peer.send(&refusal(&close, NtStatus::SUCCESS)).await;

    let shares = enumeration.await.unwrap().unwrap();
    assert_eq!(names(&shares), ["alpha", "beta", "gamma", "delta", "IPC$"]);
    assert_eq!(shares[2].comment, "three");
}

/// The paging loop's no-progress guard: a reply that adds no entries and does
/// not end the enumeration is an error rather than another round. Without it a
/// server answering `ERROR_MORE_DATA` with an empty page is asked again
/// forever.
#[tokio::test]
async fn a_page_that_adds_nothing_fails_rather_than_looping() {
    let (ipc, mut peer) = pair();
    let enumeration = tokio::spawn(async move { ipc.list_shares(SERVER).await });

    let rap = peer.request(TRANSACTION).await;
    peer.send(&refusal(&rap, NtStatus::NOT_SUPPORTED)).await;
    let create = peer.request(NT_CREATE_ANDX).await;
    peer.send(&nt_create_reply(&create)).await;
    let bind = peer.request(TRANSACTION).await;
    peer.send(&transaction_reply(
        &bind,
        NtStatus::SUCCESS,
        &[],
        &bind_ack(),
    ))
    .await;

    let call = peer.request(TRANSACTION).await;
    let page = enum_stub(&[], 7, 3, 234);
    peer.send(&transaction_reply(
        &call,
        NtStatus::SUCCESS,
        &[],
        &response_pdu(1, PFC_FIRST | PFC_LAST, &page),
    ))
    .await;

    let close = peer.request(CLOSE).await;
    peer.send(&refusal(&close, NtStatus::SUCCESS)).await;

    let error = enumeration.await.unwrap().unwrap_err();
    assert!(
        error.to_string().contains("no entries"),
        "the failure should name the empty page: {error}"
    );
    assert!(
        peer.quiet().await,
        "the client asked for another round after a page that added nothing"
    );
}

/// The enumeration is never handed to the caller with `ERROR_MORE_DATA`
/// unresolved. A server that keeps saying there is more, one share at a time,
/// is stopped by the round cap rather than followed indefinitely.
#[tokio::test]
async fn a_server_that_pages_forever_is_stopped_rather_than_followed() {
    let (ipc, mut peer) = pair();
    let enumeration = tokio::spawn(async move { ipc.list_shares(SERVER).await });

    let rap = peer.request(TRANSACTION).await;
    peer.send(&refusal(&rap, NtStatus::NOT_SUPPORTED)).await;
    let create = peer.request(NT_CREATE_ANDX).await;
    peer.send(&nt_create_reply(&create)).await;
    let bind = peer.request(TRANSACTION).await;
    peer.send(&transaction_reply(
        &bind,
        NtStatus::SUCCESS,
        &[],
        &bind_ack(),
    ))
    .await;

    let mut rounds = 0;
    loop {
        let Ok(call) = timeout(SETTLE, peer.try_frame()).await else {
            break;
        };
        let call = call.expect("a request, not the end of the stream");
        if call[4] == CLOSE {
            peer.send(&refusal(&call, NtStatus::SUCCESS)).await;
            break;
        }
        rounds += 1;
        let page = enum_stub(&[("one", 0, "")], 9999, rounds, 234);
        peer.send(&transaction_reply(
            &call,
            NtStatus::SUCCESS,
            &[],
            &response_pdu(rounds, PFC_FIRST | PFC_LAST, &page),
        ))
        .await;
    }

    assert_eq!(rounds, 64, "the round cap should have stopped the loop");
    let error = enumeration.await.unwrap().unwrap_err();
    assert!(
        error.to_string().contains("did not finish"),
        "the failure should say the enumeration never finished: {error}"
    );
}

// ===========================================================================
// Both paths failing.
// ===========================================================================

/// Both fall-throughs keep the first attempt's failure, so a caller reading the
/// message sees why each way was abandoned rather than only the last one.
#[tokio::test]
async fn both_paths_failing_says_why_each_did() {
    let (ipc, mut peer) = pair();
    let enumeration = tokio::spawn(async move { ipc.list_shares(SERVER).await });

    let rap = peer.request(TRANSACTION).await;
    peer.send(&refusal(&rap, NtStatus::NOT_SUPPORTED)).await;

    let create = peer.request(NT_CREATE_ANDX).await;
    peer.send(&nt_create_reply(&create)).await;
    let attempt = peer.request(TRANSACTION).await;
    peer.send(&refusal(&attempt, NtStatus::INVALID_HANDLE))
        .await;
    let write = peer.request(WRITE_ANDX).await;
    peer.send(&refusal(&write, NtStatus::SMB_BAD_FID)).await;
    let close = peer.request(CLOSE).await;
    peer.send(&refusal(&close, NtStatus::SUCCESS)).await;

    let error = enumeration.await.unwrap().unwrap_err();
    let message = error.to_string();
    // The RAP refusal, the transact refusal and the write refusal all survive.
    assert!(message.contains("STATUS_NOT_SUPPORTED"), "{message}");
    assert!(message.contains("STATUS_INVALID_HANDLE"), "{message}");
    assert!(message.contains("STATUS_SMB_BAD_FID"), "{message}");
    // The status a caller acts on is the one that decided the outcome.
    assert!(matches!(error, Error::BothAttemptsFailed { .. }));
    assert_eq!(error.status(), Some(NtStatus::SMB_BAD_FID));
}
