//! The connection actor, driven over the test seam against a fake transport.
//!
//! Everything here is offline and deterministic. Captured fixtures are static
//! bytes, so they prove parsing and nothing about timing, and every capture in
//! the corpus has exactly one request outstanding at a time — so what proves
//! the connection's three invariants is this suite, driving the same public
//! constructor a consumer gets.
//!
//! The timing tests run under tokio's virtual clock: the per-request timeout,
//! the overall deadline that caps its resets, and the connection-silence rule
//! cannot be reached in real time. The two reassembly guards are not in that
//! category — both are counts, reached by feeding fragments.
//!
//! `tests/COVERAGE.md` maps each invariant to the tests below.

use std::fs;
use std::path::Path;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::timeout;

use smb1client::NtStatus;
use smb1client::connection::{
    Connection, Error, Negotiated, ReassemblyError, Reply, Request, Timeouts, transport,
};

// ---------------------------------------------------------------------------
// Wire shapes, hand-built. The wire layer is not public surface, and building
// these by hand is what lets a test send bytes no server in the corpus sends.
// ---------------------------------------------------------------------------

const HEADER_LEN: usize = 32;
const MID_AT: usize = 30;

const TRANSACTION2: u8 = 0x32;
const READ_ANDX: u8 = 0x2E;
const ECHO: u8 = 0x2B;
const CLOSE: u8 = 0x04;

/// How long a test waits before concluding nothing more is coming. Under a
/// paused clock this settles the moment the actor has nothing left to do.
const SETTLE: Duration = Duration::from_millis(1);

/// Wraps an SMB message in its NetBIOS session-message header.
fn framed(message: &[u8]) -> Vec<u8> {
    let length = message.len();
    let mut out = vec![
        0x00,
        ((length >> 16) & 0x01) as u8,
        ((length >> 8) & 0xFF) as u8,
        (length & 0xFF) as u8,
    ];
    out.extend_from_slice(message);
    out
}

/// A response header.
fn response_header(command: u8, status: NtStatus, mid: u16) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(b"\xffSMB");
    header.push(command);
    header.extend_from_slice(&status.code().to_le_bytes());
    header.push(0x98);
    header.extend_from_slice(&0xC803u16.to_le_bytes());
    header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&[0u8; 8]);
    header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&1u16.to_le_bytes());
    header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&mid.to_le_bytes());
    assert_eq!(header.len(), HEADER_LEN);
    header
}

/// The shape SMB1 usually answers a command with: `WordCount = 0` and an empty
/// byte area, where the header's status is the whole of what it says.
fn bodyless(command: u8, status: NtStatus, mid: u16) -> Vec<u8> {
    let mut message = response_header(command, status, mid);
    message.push(0);
    message.extend_from_slice(&0u16.to_le_bytes());
    message
}

/// One message of a transaction reply.
#[derive(Debug, Clone)]
struct Fragment {
    mid: u16,
    status: NtStatus,
    total_parameters: u16,
    total_data: u16,
    parameter_displacement: u16,
    data_displacement: u16,
    parameters: Vec<u8>,
    data: Vec<u8>,
}

impl Fragment {
    fn new(mid: u16, total_data: u16) -> Self {
        Self {
            mid,
            status: NtStatus::SUCCESS,
            total_parameters: 0,
            total_data,
            parameter_displacement: 0,
            data_displacement: 0,
            parameters: Vec::new(),
            data: Vec::new(),
        }
    }

    fn at(mut self, displacement: u16, data: Vec<u8>) -> Self {
        self.data_displacement = displacement;
        self.data = data;
        self
    }

    fn encode(&self) -> Vec<u8> {
        let words = 10usize;
        let mut area = Vec::new();
        let mut at = HEADER_LEN + 1 + words * 2 + 2;

        let parameter_offset = if self.parameters.is_empty() {
            0
        } else {
            while !at.is_multiple_of(2) {
                area.push(0);
                at += 1;
            }
            let offset = at;
            area.extend_from_slice(&self.parameters);
            at += self.parameters.len();
            offset
        };
        while !at.is_multiple_of(2) {
            area.push(0);
            at += 1;
        }
        let data_offset = at;
        area.extend_from_slice(&self.data);

        let mut block = Vec::new();
        for word in [
            self.total_parameters,
            self.total_data,
            0,
            self.parameters.len() as u16,
            parameter_offset as u16,
            self.parameter_displacement,
            self.data.len() as u16,
            data_offset as u16,
            self.data_displacement,
        ] {
            block.extend_from_slice(&word.to_le_bytes());
        }
        block.extend_from_slice(&[0, 0]);
        assert_eq!(block.len(), words * 2);

        let mut message = response_header(TRANSACTION2, self.status, self.mid);
        message.push(words as u8);
        message.extend_from_slice(&block);
        message.extend_from_slice(&(area.len() as u16).to_le_bytes());
        message.extend_from_slice(&area);
        message
    }
}

/// The multiplex id a frame carries.
fn mid_of(message: &[u8]) -> u16 {
    u16::from_le_bytes([message[MID_AT], message[MID_AT + 1]])
}

/// The command a frame carries.
fn command_of(message: &[u8]) -> u8 {
    message[4]
}

// ---------------------------------------------------------------------------
// The fake transport.
// ---------------------------------------------------------------------------

/// The far side of the connection: whatever a test wants a server to be.
struct Peer {
    stream: DuplexStream,
}

impl Peer {
    /// Reads one frame, its NetBIOS header stripped. `None` at end of stream,
    /// which is what the actor ending looks like from here.
    async fn try_frame(&mut self) -> Option<Vec<u8>> {
        let mut header = [0u8; 4];
        match self.stream.read_exact(&mut header).await {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return None,
            Err(error) => panic!("reading a NetBIOS header: {error}"),
        }
        assert_eq!(header[0], 0x00, "the client sent a non-session message");
        let length = (usize::from(header[1] & 0x01) << 16)
            | usize::from(u16::from_be_bytes([header[2], header[3]]));
        let mut message = vec![0; length];
        self.stream
            .read_exact(&mut message)
            .await
            .expect("a whole frame");
        Some(message)
    }

    async fn frame(&mut self) -> Vec<u8> {
        self.try_frame()
            .await
            .expect("a frame, not the end of the stream")
    }

    /// The next frame, or `None` where nothing more is coming.
    async fn next_frame(&mut self) -> Option<Vec<u8>> {
        timeout(SETTLE, self.try_frame()).await.ok().flatten()
    }

    /// Every frame the client has sent and not been answered for.
    async fn drain(&mut self) -> Vec<Vec<u8>> {
        let mut frames = Vec::new();
        while let Some(frame) = self.next_frame().await {
            frames.push(frame);
        }
        frames
    }

    async fn send(&mut self, message: &[u8]) {
        self.stream
            .write_all(&framed(message))
            .await
            .expect("the client is reading");
    }

    async fn send_raw(&mut self, bytes: &[u8]) {
        self.stream
            .write_all(bytes)
            .await
            .expect("the client is reading");
    }

    /// Whether the actor has ended, which the peer sees as end of stream once
    /// it has read whatever the client wrote before it went.
    async fn ended(&mut self) -> bool {
        loop {
            match timeout(SETTLE, self.try_frame()).await {
                Ok(None) => return true,
                Ok(Some(_)) => continue,
                Err(_) => return false,
            }
        }
    }
}

/// A connection over a duplex pair, with the negotiated parameters injected.
fn pair(max_mpx_count: u16, timeouts: Timeouts) -> (Connection, Peer) {
    buffered_pair(max_mpx_count, timeouts, 256 * 1024)
}

fn buffered_pair(max_mpx_count: u16, timeouts: Timeouts, buffer: usize) -> (Connection, Peer) {
    let (client, server) = tokio::io::duplex(buffer);
    let connection = transport::spawn(
        client,
        Negotiated {
            max_mpx_count,
            max_buffer_size: 65_535,
            capabilities: 0,
        },
        timeouts,
    );
    (connection, Peer { stream: server })
}

/// A request whose reply arrives in one message.
fn echo() -> Request {
    Request::new(ECHO, 0xFFFF, 0, vec![1, 0, 0, 0, 0])
}

/// A transaction, which is what reassembly happens for.
fn trans2() -> Request {
    Request::transaction(TRANSACTION2, 1, 1, vec![0; 40], 64, 65_472)
}

fn fixture(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name);
    let bytes = fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    bytes[4..].to_vec()
}

// ===========================================================================
// Invariant 1 — a caller never observes a partial transaction.
// ===========================================================================

/// **Invariant 1.** The distinguishing content of the rule: coverage of the
/// declared ranges, never a running sum of byte counts.
///
/// Three fragments of a 300-byte reply, at displacements 0, 200 and 150. Their
/// byte counts sum to exactly 300 while 100..150 was never sent, so a
/// reassembler that counts bytes declares the reply complete and hands the
/// caller 300 bytes with a 50-byte zero-filled hole in the middle of it — the
/// silent corruption this invariant exists to forbid, arriving through the very
/// check meant to prevent it. A coverage map sees the third fragment re-cover
/// 200..250 and refuses it, the overlap being a protocol error in its own
/// right: a server contradicting itself about its own reply's bytes.
///
/// No capture in the corpus holds an overlapping or gapped fragment, which is
/// why this sequence is hand-built.
#[tokio::test(start_paused = true)]
async fn invariant_1_coverage_refuses_what_a_running_sum_accepts() {
    let (connection, mut peer) = pair(50, Timeouts::default());
    let issuer = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(trans2()).await }
    });

    let mid = mid_of(&peer.frame().await);
    peer.send(&Fragment::new(mid, 300).at(0, vec![0xAA; 100]).encode())
        .await;
    peer.send(&Fragment::new(mid, 300).at(200, vec![0xBB; 100]).encode())
        .await;
    // 100 + 100 + 100 == 300, the declared total, and 100..150 is a hole.
    peer.send(&Fragment::new(mid, 300).at(150, vec![0xCC; 100]).encode())
        .await;

    match issuer.await.expect("the issuing task did not panic") {
        Err(Error::Reassembly(ReassemblyError::Overlapping {
            block,
            displacement,
            length,
        })) => {
            assert_eq!(block, "data");
            assert_eq!(displacement, 150);
            assert_eq!(length, 100);
        }
        Ok(reply) => {
            let data = reply.transaction().expect("a transaction body").data();
            let hole = &data[100..150];
            panic!(
                "a partial transaction was delivered: {} bytes, of which {}..{} were never sent \
                 and arrived as {:?} — a running sum of byte counts reached the declared total \
                 while the reply had a hole in it",
                data.len(),
                100,
                150,
                &hole[..8.min(hole.len())]
            );
        }
        Err(other) => panic!("the overlap was reported as something else: {other}"),
    }

    // The reassembly was corrupted, not the framing: one request failed and the
    // connection carries on.
    let (again, _) = round_trip(&connection, &mut peer).await;
    assert_ne!(
        again, mid,
        "a corrupted reply's multiplex id is not reissued"
    );
}

/// Issues an echo and answers it, which is proof the connection still works.
/// Returns the multiplex id it went out on.
async fn round_trip(connection: &Connection, peer: &mut Peer) -> (u16, Reply) {
    let issuer = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(echo()).await }
    });
    let mid = mid_of(&peer.frame().await);
    peer.send(&bodyless(ECHO, NtStatus::SUCCESS, mid)).await;
    let reply = issuer
        .await
        .expect("the issuing task did not panic")
        .expect("the echo is answered");
    (mid, reply)
}

/// **Invariant 1.** A hole that no overlap papers over never completes either:
/// the reply is owed bytes forever and the request lapses rather than being
/// delivered short.
#[tokio::test(start_paused = true)]
async fn invariant_1_a_gapped_reply_is_never_delivered() {
    let timeouts = Timeouts::default();
    let (connection, mut peer) = pair(50, timeouts);
    let issuer = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(trans2()).await }
    });

    let mid = mid_of(&peer.frame().await);
    peer.send(&Fragment::new(mid, 300).at(0, vec![0xAA; 100]).encode())
        .await;
    peer.send(&Fragment::new(mid, 300).at(200, vec![0xBB; 100]).encode())
        .await;

    assert!(
        peer.next_frame().await.is_none(),
        "nothing more should reach the wire"
    );
    let start = tokio::time::Instant::now();
    tokio::time::advance(timeouts.per_request + Duration::from_secs(1)).await;

    match issuer.await.expect("the issuing task did not panic") {
        Err(Error::Timeout) => assert!(
            start.elapsed() < timeouts.per_request + Duration::from_secs(5),
            "the request lapsed only after {:?}",
            start.elapsed()
        ),
        Ok(reply) => panic!(
            "200 of 300 declared bytes were delivered as a whole reply: {} bytes",
            reply
                .transaction()
                .expect("a transaction body")
                .data()
                .len()
        ),
        Err(other) => panic!("unexpected error: {other}"),
    }
}

/// **Invariant 1.** The reassembly path itself, over the committed fixture: a
/// FIND_FIRST2 reply Samba split across two messages, replayed through the
/// actor and delivered as one.
///
/// The trailing entry of the first message begins 176 bytes before that
/// message's data ends and continues in the second, so a reply delivered from
/// either message alone is a reply the entry chain cannot be walked over.
#[tokio::test(start_paused = true)]
async fn invariant_1_a_fragmented_reply_is_delivered_whole() {
    let request = fixture("capture-frag/0009-c2s-cmd32.bin");
    let first = fixture("capture-frag/0010-s2c-cmd32.bin");
    let second = fixture("capture-frag/0011-s2c-cmd32.bin");

    // The request's own MaxParameterCount and MaxDataCount are what bound the
    // reassembly, so they are read from the captured request rather than
    // invented.
    let words = &request[HEADER_LEN + 1..];
    let max_parameter_count = u16::from_le_bytes([words[4], words[5]]);
    let max_data_count = u16::from_le_bytes([words[6], words[7]]);

    let (connection, mut peer) = pair(50, Timeouts::default());
    let issuer = tokio::spawn({
        let connection = connection.clone();
        async move {
            connection
                .request(Request::transaction(
                    TRANSACTION2,
                    1,
                    1,
                    request[HEADER_LEN..].to_vec(),
                    max_parameter_count,
                    max_data_count,
                ))
                .await
        }
    });

    let mid = mid_of(&peer.frame().await);
    peer.send(&with_mid(&first, mid)).await;
    assert!(
        peer.next_frame().await.is_none(),
        "the reply is not complete after one message"
    );
    peer.send(&with_mid(&second, mid)).await;

    let reply = issuer
        .await
        .expect("the issuing task did not panic")
        .expect("the reply reassembles");
    let body = reply.transaction().expect("a transaction body");
    assert_eq!(body.parameters().len(), 10);
    assert_eq!(body.data().len(), 17_836);
    // 16,572 bytes from the first message and 1,264 from the second, in the
    // order their displacements put them.
    assert!(body.data()[..16_572].iter().any(|&byte| byte != 0));
    assert_eq!(&body.data()[16_572..16_580], &data_of(&second)[..8]);
}

/// **Invariant 1.** A reply may not return more than the request asked for. The
/// bound comes from the client side, never from the totals a server declares.
#[tokio::test(start_paused = true)]
async fn invariant_1_a_reply_larger_than_the_request_allowed_fails_it() {
    let (connection, mut peer) = pair(50, Timeouts::default());
    let issuer = tokio::spawn({
        let connection = connection.clone();
        async move {
            connection
                .request(Request::transaction(
                    TRANSACTION2,
                    1,
                    1,
                    vec![0; 40],
                    64,
                    1_024,
                ))
                .await
        }
    });

    let mid = mid_of(&peer.frame().await);
    peer.send(&Fragment::new(mid, 4_096).at(0, vec![0; 100]).encode())
        .await;

    assert!(matches!(
        issuer.await.expect("no panic"),
        Err(Error::Reassembly(ReassemblyError::MoreThanAsked {
            total: 4_096,
            asked: 1_024,
            ..
        }))
    ));
}

/// Replaces a captured reply's multiplex id with the one the actor issued.
fn with_mid(message: &[u8], mid: u16) -> Vec<u8> {
    let mut out = message.to_vec();
    out[MID_AT..MID_AT + 2].copy_from_slice(&mid.to_le_bytes());
    out
}

/// The data block of a captured transaction reply, read at the offset it
/// declares.
fn data_of(message: &[u8]) -> Vec<u8> {
    let words = &message[HEADER_LEN + 1..];
    let count = usize::from(u16::from_le_bytes([words[12], words[13]]));
    let offset = usize::from(u16::from_le_bytes([words[14], words[15]]));
    message[offset..offset + count].to_vec()
}

// ===========================================================================
// Invariant 2 — no response is discarded silently.
// ===========================================================================

/// A request the peer can tell apart from the others in flight.
fn tagged(tag: u8) -> Request {
    Request::transaction(TRANSACTION2, 1, 1, vec![tag; 40], 64, 65_472)
}

/// The tag a request carries, read out of the frame the peer received.
fn tag_of(message: &[u8]) -> u8 {
    message[HEADER_LEN]
}

/// **Invariant 2.** Several requests outstanding at once, answered out of
/// order, with every frame that is not an ordinary reply driven through the
/// same connection: a NetBIOS keep-alive, an interim `STATUS_PENDING`, a reply
/// split across two messages, and a bodyless error status.
///
/// Each caller gets its own reply and no other, which is what says routing did
/// not silently cross two requests or drop one.
#[tokio::test(start_paused = true)]
async fn invariant_2_every_frame_reaches_its_own_request() {
    let (connection, mut peer) = pair(4, Timeouts::default());

    let mut callers = Vec::new();
    for tag in 1..=4u8 {
        let connection = connection.clone();
        callers.push((
            tag,
            tokio::spawn(async move { connection.request(tagged(tag)).await }),
        ));
    }

    let mut mids = std::collections::BTreeMap::new();
    for frame in peer.drain().await {
        assert_eq!(command_of(&frame), TRANSACTION2);
        assert!(
            mids.insert(tag_of(&frame), mid_of(&frame)).is_none(),
            "two requests went out on one multiplex id"
        );
    }
    assert_eq!(mids.len(), 4, "the whole admission limit reached the wire");

    // Transport-level and carrying nothing: the one exception to nothing being
    // discarded.
    peer.send_raw(&[0x85, 0x00, 0x00, 0x00]).await;
    // Neither a fragment nor an error: the server saying it is still working.
    peer.send(&bodyless(TRANSACTION2, NtStatus::PENDING, mids[&1]))
        .await;

    // Out of order, and one of them split across two messages.
    peer.send(&Fragment::new(mids[&3], 8).at(0, vec![3; 8]).encode())
        .await;
    peer.send(&Fragment::new(mids[&1], 8).at(4, vec![1; 4]).encode())
        .await;
    peer.send(&bodyless(TRANSACTION2, NtStatus::NO_SUCH_FILE, mids[&4]))
        .await;
    peer.send(&Fragment::new(mids[&1], 8).at(0, vec![1; 4]).encode())
        .await;
    peer.send(&Fragment::new(mids[&2], 8).at(0, vec![2; 8]).encode())
        .await;

    for (tag, caller) in callers {
        let reply = caller
            .await
            .expect("the issuing task did not panic")
            .expect("every request is answered");
        if tag == 4 {
            assert_eq!(reply.status(), NtStatus::NO_SUCH_FILE);
            assert!(reply.transaction().is_none());
        } else {
            assert_eq!(reply.status(), NtStatus::SUCCESS);
            assert_eq!(
                reply.transaction().expect("a transaction body").data(),
                &[tag; 8],
                "request {tag} was answered with another request's bytes"
            );
        }
    }
}

/// **Invariant 2.** Dropping a future withdraws nothing from the wire, so the
/// reply reaches the request that made it rather than being discarded — and the
/// request goes on charging capacity until it does.
///
/// With an admission limit of one, whether the next request reaches the wire is
/// exactly the question of whether the abandoned request is still outstanding.
#[tokio::test(start_paused = true)]
async fn invariant_2_a_reply_to_an_abandoned_request_reaches_it() {
    let (connection, mut peer) = pair(1, Timeouts::default());

    let abandoned = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(tagged(1)).await }
    });
    let mid = mid_of(&peer.frame().await);

    abandoned.abort();
    let _ = abandoned.await;

    let next = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(tagged(2)).await }
    });
    assert!(
        peer.next_frame().await.is_none(),
        "an abandoned request goes on charging capacity: nothing else may reach the wire"
    );

    // The reply reaches the request nobody is waiting on, which ends it and
    // frees the capacity it was charging.
    peer.send(&Fragment::new(mid, 8).at(0, vec![1; 8]).encode())
        .await;
    let frame = peer.frame().await;
    assert_eq!(tag_of(&frame), 2);
    peer.send(&Fragment::new(mid_of(&frame), 8).at(0, vec![2; 8]).encode())
        .await;
    assert_eq!(
        next.await.unwrap().unwrap().transaction().unwrap().data(),
        &[2; 8]
    );
}

/// **Invariant 2.** A frame on a multiplex id the connection has retired routes
/// to the retired identity, is logged against it and discarded — it is not an
/// unroutable frame, and the connection carries on.
///
/// That is what makes the rules written around a server that goes on sending
/// true as stated.
#[tokio::test(start_paused = true)]
async fn invariant_2_a_frame_on_a_retired_id_is_discarded() {
    let (connection, mut peer) = pair(50, Timeouts::default());

    let issuer = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(tagged(1)).await }
    });
    let retired = mid_of(&peer.frame().await);
    peer.send(&Fragment::new(retired, 300).at(0, vec![0xAA; 100]).encode())
        .await;
    peer.send(&Fragment::new(retired, 300).at(50, vec![0xBB; 100]).encode())
        .await;
    assert!(matches!(
        issuer.await.unwrap(),
        Err(Error::Reassembly(ReassemblyError::Overlapping { .. }))
    ));

    // The server goes on sending against the request this client gave up on.
    peer.send(
        &Fragment::new(retired, 300)
            .at(100, vec![0xCC; 100])
            .encode(),
    )
    .await;
    peer.send(&bodyless(TRANSACTION2, NtStatus::SUCCESS, retired))
        .await;

    let (fresh, _) = round_trip(&connection, &mut peer).await;
    assert_ne!(fresh, retired, "a retired id is withheld from the pool");
}

/// **Invariant 2.** A frame that routes to no request at all fails the
/// connection: the server sent something the design does not model, and
/// carrying on past it risks misrouting the next one.
#[tokio::test(start_paused = true)]
async fn invariant_2_an_unroutable_frame_fails_the_connection() {
    let (connection, mut peer) = pair(4, Timeouts::default());
    let issuer = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(echo()).await }
    });
    let mid = mid_of(&peer.frame().await);

    peer.send(&bodyless(ECHO, NtStatus::SUCCESS, mid.wrapping_add(7)))
        .await;

    assert!(matches!(issuer.await.unwrap(), Err(Error::Lost)));
    assert!(peer.ended().await, "the connection is torn down");
}

/// **Invariant 2.** Routing is by multiplex id, and the reply's command must
/// match the request's as well — a cheap backstop against the crosstalk the id
/// alone cannot exclude. The reference library carries on past such a frame
/// without even logging it.
#[tokio::test(start_paused = true)]
async fn invariant_2_a_reply_under_the_wrong_command_is_unroutable() {
    let (connection, mut peer) = pair(4, Timeouts::default());
    let issuer = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(echo()).await }
    });
    let mid = mid_of(&peer.frame().await);

    peer.send(&bodyless(READ_ANDX, NtStatus::SUCCESS, mid))
        .await;

    assert!(matches!(issuer.await.unwrap(), Err(Error::Lost)));
    assert!(peer.ended().await);
}

/// **Invariant 2.** This crate chains nothing, so a response claiming to chain
/// another command is the server answering something that was not asked, and
/// parsing on into the chain is how a decoder loses frame boundaries.
#[tokio::test(start_paused = true)]
async fn invariant_2_a_chained_response_fails_the_connection() {
    let (connection, mut peer) = pair(4, Timeouts::default());
    let issuer = tokio::spawn({
        let connection = connection.clone();
        async move {
            connection
                .request(Request::new(READ_ANDX, 1, 1, vec![0; 30]))
                .await
        }
    });
    let mid = mid_of(&peer.frame().await);

    // A `READ_ANDX` response whose AndXCommand names `WRITE_ANDX` rather than
    // the `0xFF` that says nothing follows.
    let mut message = response_header(READ_ANDX, NtStatus::SUCCESS, mid);
    message.push(12);
    message.extend_from_slice(&[0x2F, 0x00]);
    message.extend_from_slice(&[0u8; 22]);
    message.extend_from_slice(&0u16.to_le_bytes());
    peer.send(&message).await;

    assert!(matches!(issuer.await.unwrap(), Err(Error::Lost)));
    assert!(peer.ended().await);
}

/// **Invariant 2.** A NetBIOS message type the port does not recognise fails
/// the connection: reading past a frame it does not understand is how a parser
/// ends up confused about frame boundaries.
#[tokio::test(start_paused = true)]
async fn invariant_2_an_unknown_netbios_type_fails_the_connection() {
    let (connection, mut peer) = pair(4, Timeouts::default());
    let issuer = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(echo()).await }
    });
    let _ = peer.frame().await;

    peer.send_raw(&[0x81, 0x00, 0x00, 0x44]).await;

    assert!(matches!(issuer.await.unwrap(), Err(Error::Lost)));
    assert!(peer.ended().await);
}

/// **Invariant 2.** `STATUS_USER_SESSION_DELETED` is session-scoped, and a
/// connection carries exactly one session, so it fails the connection — after
/// the reply has reached the caller that asked for it, which is what stops the
/// status being lost behind a bare connection loss.
#[tokio::test(start_paused = true)]
async fn a_deleted_session_fails_the_connection_after_the_reply_lands() {
    let (connection, mut peer) = pair(4, Timeouts::default());
    let first = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(echo()).await }
    });
    let doomed = mid_of(&peer.frame().await);
    let second = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(echo()).await }
    });
    let _ = peer.frame().await;

    peer.send(&bodyless(ECHO, NtStatus::USER_SESSION_DELETED, doomed))
        .await;

    assert_eq!(
        first.await.unwrap().unwrap().status(),
        NtStatus::USER_SESSION_DELETED
    );
    assert!(matches!(second.await.unwrap(), Err(Error::Lost)));
    assert!(peer.ended().await);
}

// ===========================================================================
// Invariant 3 — admission never exceeds the negotiated limit.
// ===========================================================================

/// **Invariant 3.** However many tasks a consumer runs, `|Live| + |Orphaned|`
/// never exceeds `min(negotiated MaxMpxCount, 50)`.
///
/// Twenty tasks against a server that negotiated four. Exactly four frames
/// reach the wire, and the fifth only once a reply has ended one of them.
#[tokio::test(start_paused = true)]
async fn invariant_3_admission_never_exceeds_the_negotiated_limit() {
    let (connection, mut peer) = pair(4, Timeouts::default());
    let mut callers = Vec::new();
    for tag in 1..=20u8 {
        let connection = connection.clone();
        callers.push(tokio::spawn(async move {
            connection.request(tagged(tag)).await
        }));
    }

    let outstanding = peer.drain().await;
    assert_eq!(
        outstanding.len(),
        4,
        "the negotiated MaxMpxCount is what bounds the wire, not the ceiling of 50"
    );

    peer.send(
        &Fragment::new(mid_of(&outstanding[0]), 8)
            .at(0, vec![0; 8])
            .encode(),
    )
    .await;
    assert_eq!(
        peer.drain().await.len(),
        1,
        "one reply frees one slot and no more"
    );

    for caller in callers {
        caller.abort();
        let _ = caller.await;
    }
}

/// **Invariant 3.** A caller dropping its future withdraws nothing from the
/// wire, so the request it abandoned goes on charging capacity. Ceasing to
/// charge at the drop would put requests the server is still working on over
/// the negotiated ceiling with no bound at all.
#[tokio::test(start_paused = true)]
async fn invariant_3_abandoned_requests_go_on_charging_capacity() {
    let (connection, mut peer) = pair(3, Timeouts::default());
    let mut callers = Vec::new();
    for tag in 1..=3u8 {
        let connection = connection.clone();
        callers.push(tokio::spawn(async move {
            connection.request(tagged(tag)).await
        }));
    }
    let outstanding = peer.drain().await;
    assert_eq!(outstanding.len(), 3);

    for caller in callers {
        caller.abort();
        let _ = caller.await;
    }

    let mut waiting = Vec::new();
    for tag in 4..=6u8 {
        let connection = connection.clone();
        waiting.push(tokio::spawn(async move {
            connection.request(tagged(tag)).await
        }));
    }
    assert!(
        peer.drain().await.is_empty(),
        "three orphaned requests still fill a limit of three"
    );

    peer.send(
        &Fragment::new(mid_of(&outstanding[1]), 8)
            .at(0, vec![0; 8])
            .encode(),
    )
    .await;
    assert_eq!(peer.drain().await.len(), 1);

    for caller in waiting {
        caller.abort();
        let _ = caller.await;
    }
}

/// **Invariant 3.** A server reporting a `MaxMpxCount` of 0 or 1 is saying it
/// does not multiplex, so the connection is serial.
#[tokio::test(start_paused = true)]
async fn invariant_3_a_server_that_does_not_multiplex_is_serial() {
    for reported in [0u16, 1] {
        let (connection, mut peer) = pair(reported, Timeouts::default());
        assert_eq!(connection.negotiated().admission_limit(), 1);
        let mut callers = Vec::new();
        for tag in 1..=5u8 {
            let connection = connection.clone();
            callers.push(tokio::spawn(async move {
                connection.request(tagged(tag)).await
            }));
        }
        assert_eq!(
            peer.drain().await.len(),
            1,
            "a MaxMpxCount of {reported} means one request at a time"
        );
        for caller in callers {
            caller.abort();
            let _ = caller.await;
        }
    }
}

/// **Invariant 3.** The inherited ceiling of 50 caps a server that reports
/// more. Its job is to bound reassembly memory: a request holding a reassembly
/// buffer is a request charging capacity.
#[tokio::test(start_paused = true)]
async fn invariant_3_the_ceiling_caps_a_generous_server() {
    let (connection, mut peer) = pair(200, Timeouts::default());
    assert_eq!(connection.negotiated().admission_limit(), 50);
    let mut callers = Vec::new();
    for _ in 0..120 {
        let connection = connection.clone();
        callers.push(tokio::spawn(
            async move { connection.request(echo()).await },
        ));
    }
    assert_eq!(peer.drain().await.len(), 50);
    for caller in callers {
        caller.abort();
        let _ = caller.await;
    }
}

// ===========================================================================
// Timing. None of this is reachable in real time, so it runs on tokio's
// virtual clock — the direct equivalent of Go's `testing/synctest`.
// ===========================================================================

/// The per-request timeout measures silence, not elapsed work: any message that
/// reaches a request still charging capacity resets it.
///
/// Three fragments twenty-five seconds apart carry a request through
/// seventy-five seconds of a thirty-second timeout, because a server streaming
/// a large listing across many messages is answering.
#[tokio::test(start_paused = true)]
async fn the_per_request_clock_measures_silence() {
    let timeouts = Timeouts::default();
    let (connection, mut peer) = pair(4, timeouts);
    let issuer = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(tagged(1)).await }
    });
    let mid = mid_of(&peer.frame().await);

    for displacement in [0u16, 4, 8] {
        tokio::time::advance(Duration::from_secs(25)).await;
        peer.send(&Fragment::new(mid, 12).at(displacement, vec![1; 4]).encode())
            .await;
    }

    assert_eq!(
        issuer.await.unwrap().unwrap().transaction().unwrap().data(),
        &[1; 12],
        "a request answered steadily is not lapsed mid-stream"
    );
}

/// An interim response resets the same clock as a fragment that contributes
/// bytes, and counts against neither reassembly guard: counting it would fail a
/// legitimate reassembly on the second interim, which is a slow server saying
/// it is still working.
#[tokio::test(start_paused = true)]
async fn status_pending_resets_the_clock_and_counts_against_no_guard() {
    let timeouts = Timeouts::default();
    let (connection, mut peer) = pair(4, timeouts);
    let issuer = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(tagged(1)).await }
    });
    let mid = mid_of(&peer.frame().await);

    // Far past both the fragment cap of 64 and the tolerance of one
    // contribution-free message, and several times over the per-request timeout
    // — while staying inside the overall deadline, which caps every reset.
    for _ in 0..100 {
        tokio::time::advance(Duration::from_secs(2)).await;
        peer.send(&bodyless(TRANSACTION2, NtStatus::PENDING, mid))
            .await;
    }
    peer.send(&Fragment::new(mid, 4).at(0, vec![1; 4]).encode())
        .await;

    assert_eq!(
        issuer.await.unwrap().unwrap().transaction().unwrap().data(),
        &[1; 4]
    );
}

/// The overall deadline is what stops a server that resets the clock
/// indefinitely from charging capacity for ever.
#[tokio::test(start_paused = true)]
async fn the_overall_deadline_caps_the_resets() {
    let timeouts = Timeouts::default();
    let (connection, mut peer) = pair(4, timeouts);
    let issuer = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(tagged(1)).await }
    });
    let mid = mid_of(&peer.frame().await);

    // A fragment every twenty seconds, each contributing a byte: the
    // per-request clock never expires, and the deadline does. What is asserted
    // is *when* — awaiting a request that never lapses would let the paused
    // clock run on to whatever deadline was left and time out there, so the
    // outcome alone proves nothing.
    let start = tokio::time::Instant::now();
    for displacement in 0..40u16 {
        tokio::time::advance(Duration::from_secs(20)).await;
        if issuer.is_finished() {
            break;
        }
        peer.send(
            &Fragment::new(mid, 4_000)
                .at(displacement, vec![1; 1])
                .encode(),
        )
        .await;
    }
    let lapsed_after = start.elapsed();

    assert!(
        matches!(issuer.await.unwrap(), Err(Error::Timeout)),
        "a request making progress for ever is still bounded by the overall deadline"
    );
    assert!(
        lapsed_after < timeouts.overall + Duration::from_secs(60),
        "the request went on charging capacity for {lapsed_after:?}, past the {:?} deadline",
        timeouts.overall
    );
}

/// Time spent waiting for capacity does not consume the per-request timeout:
/// the clock starts at dispatch, at the first byte on the socket.
#[tokio::test(start_paused = true)]
async fn waiting_for_capacity_does_not_consume_the_timeout() {
    let timeouts = Timeouts::default();
    let (connection, mut peer) = pair(1, timeouts);

    let first = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(tagged(1)).await }
    });
    let held = mid_of(&peer.frame().await);

    let queued = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(tagged(2)).await }
    });
    assert!(peer.next_frame().await.is_none());

    // Twenty-five seconds behind the connection's one slot.
    tokio::time::advance(Duration::from_secs(25)).await;
    peer.send(&Fragment::new(held, 4).at(0, vec![1; 4]).encode())
        .await;
    let mid = mid_of(&peer.frame().await);

    // Fifty seconds after the caller asked, and twenty-five after the request
    // reached the wire: inside its own timeout and well past a clock that had
    // started when it was enqueued.
    tokio::time::advance(Duration::from_secs(25)).await;
    peer.send(&Fragment::new(mid, 4).at(0, vec![2; 4]).encode())
        .await;

    assert_eq!(
        first.await.unwrap().unwrap().transaction().unwrap().data(),
        &[1; 4]
    );
    assert_eq!(
        queued.await.unwrap().unwrap().transaction().unwrap().data(),
        &[2; 4],
        "the queued request's clock started when it reached the wire"
    );
}

/// A lapsed request keeps its multiplex id until its reply arrives whole, and a
/// complete late reply gives that id back — after which the id is neither held
/// nor remembered, so a further frame on it is unroutable.
#[tokio::test(start_paused = true)]
async fn a_complete_late_reply_returns_a_lapsed_request_s_id() {
    let timeouts = Timeouts::default();
    let (connection, mut peer) = pair(2, timeouts);
    let issuer = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(tagged(1)).await }
    });
    let lapsed = mid_of(&peer.frame().await);

    let start = tokio::time::Instant::now();
    tokio::time::advance(timeouts.per_request + Duration::from_secs(1)).await;
    assert!(matches!(issuer.await.unwrap(), Err(Error::Timeout)));
    assert!(
        start.elapsed() < timeouts.per_request + Duration::from_secs(5),
        "the request lapsed only after {:?}",
        start.elapsed()
    );

    // Still holding its id: a partial reply keeps it reserved for exactly as
    // long as the server may still be sending.
    peer.send(&Fragment::new(lapsed, 8).at(0, vec![9; 4]).encode())
        .await;
    round_trip(&connection, &mut peer).await;

    // The complete reply is the proof the server is finished with the id.
    peer.send(&Fragment::new(lapsed, 8).at(4, vec![9; 4]).encode())
        .await;
    round_trip(&connection, &mut peer).await;

    peer.send(&Fragment::new(lapsed, 8).at(0, vec![9; 8]).encode())
        .await;
    assert!(
        peer.ended().await,
        "an id back in the pool is not remembered, so a frame on it routes to nothing"
    );
}

/// A lapsed request whose reply never comes is given up on after eight overall
/// deadlines, and its multiplex id is retired rather than returned. **That
/// clock runs from the lapse and nothing resets it**: a message arriving at a
/// lapsed request advances the coverage it is still tracking and buys no more
/// time.
#[tokio::test(start_paused = true)]
async fn a_lapsed_request_is_given_up_on_and_its_id_retired() {
    let timeouts = Timeouts::default();
    let (connection, mut peer) = pair(2, timeouts);
    let issuer = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(tagged(1)).await }
    });
    let lapsed = mid_of(&peer.frame().await);

    let start = tokio::time::Instant::now();
    tokio::time::advance(timeouts.per_request + Duration::from_secs(1)).await;
    assert!(matches!(issuer.await.unwrap(), Err(Error::Timeout)));
    assert!(
        start.elapsed() < timeouts.per_request + Duration::from_secs(5),
        "the request lapsed only after {:?}",
        start.elapsed()
    );

    // A server dribbling messages at a request nobody waits on, for the whole
    // of the eight deadlines. Were the give-up clock reset by them, the id
    // would be held for as long as the server cared to keep sending.
    for displacement in 0..8u16 {
        tokio::time::advance(timeouts.overall).await;
        peer.send(
            &Fragment::new(lapsed, 4_000)
                .at(displacement, vec![9; 1])
                .encode(),
        )
        .await;
    }
    tokio::time::advance(timeouts.overall).await;

    // A complete response on that id. A request still Lapsed would take it as
    // its reply and hand the id back to the pool, after which the second one
    // would route to nothing and fail the connection. A retired identity
    // discards both and the connection carries on.
    peer.send(&bodyless(TRANSACTION2, NtStatus::NO_SUCH_FILE, lapsed))
        .await;
    peer.send(&bodyless(TRANSACTION2, NtStatus::NO_SUCH_FILE, lapsed))
        .await;
    let (fresh, _) = round_trip(&connection, &mut peer).await;
    assert_ne!(fresh, lapsed);
}

/// A connection fails when no message of any kind has arrived for one overall
/// deadline while at least one request is still waiting.
///
/// The caller here is the case the rule is written against: a silent drop with
/// no FIN otherwise costs every later call a full per-request timeout, for
/// ever, and the entry is never re-dialled.
#[tokio::test(start_paused = true)]
async fn the_connection_fails_after_one_deadline_of_silence() {
    let timeouts = Timeouts::default();
    let (connection, mut peer) = pair(1, timeouts);
    let caller = tokio::spawn(async move {
        loop {
            match connection.request(echo()).await {
                Err(Error::Timeout) => continue,
                Err(Error::Lost) => return,
                other => panic!("unexpected outcome: {other:?}"),
            }
        }
    });

    let start = tokio::time::Instant::now();
    timeout(timeouts.overall * 3, caller)
        .await
        .expect("the connection is failed by the silence rule")
        .expect("the calling task did not panic");
    assert!(
        start.elapsed() < timeouts.overall + Duration::from_secs(60),
        "the connection survived {:?} of silence with a caller waiting throughout",
        start.elapsed()
    );
    assert!(peer.ended().await);
}

/// An idle connection is not failed by the silence rule: it needs a request
/// outstanding to measure, and a connection nobody is asking anything of is
/// left to the cache's probe instead.
#[tokio::test(start_paused = true)]
async fn silence_on_an_idle_connection_fails_nothing() {
    let timeouts = Timeouts::default();
    let (connection, mut peer) = pair(4, timeouts);
    round_trip(&connection, &mut peer).await;

    for _ in 0..20 {
        tokio::time::advance(timeouts.overall).await;
    }

    round_trip(&connection, &mut peer).await;
}

// ===========================================================================
// The reassembly guards. Both are counts, reached by feeding fragments.
// ===========================================================================

/// The fragment cap terminates a server that never signals completion.
#[tokio::test(start_paused = true)]
async fn the_fragment_cap_ends_a_reply_that_never_finishes() {
    let (connection, mut peer) = pair(4, Timeouts::default());
    let issuer = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(tagged(1)).await }
    });
    let mid = mid_of(&peer.frame().await);

    for displacement in 0..65u16 {
        peer.send(
            &Fragment::new(mid, 4_000)
                .at(displacement, vec![1; 1])
                .encode(),
        )
        .await;
    }

    assert!(matches!(
        issuer.await.unwrap(),
        Err(Error::Reassembly(ReassemblyError::TooManyFragments(64)))
    ));
}

/// The contribution-free tolerance is what does the real work of terminating a
/// server that keeps sending: the second message that carries nothing ends the
/// reassembly, long before the sixty-fifth fragment would.
#[tokio::test(start_paused = true)]
async fn a_second_contribution_free_message_ends_the_reassembly() {
    let (connection, mut peer) = pair(4, Timeouts::default());
    let issuer = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(tagged(1)).await }
    });
    let mid = mid_of(&peer.frame().await);

    peer.send(&Fragment::new(mid, 4_000).at(0, vec![1; 8]).encode())
        .await;
    peer.send(&Fragment::new(mid, 4_000).encode()).await;
    peer.send(&Fragment::new(mid, 4_000).encode()).await;

    assert!(matches!(
        issuer.await.unwrap(),
        Err(Error::Reassembly(ReassemblyError::NoProgress))
    ));
}

// ===========================================================================
// The actor loop: the write in progress, and the bias in the `select`.
// ===========================================================================

/// A blocked socket write never stops the actor reading replies or firing
/// timers.
///
/// An actor that ran the write to completion inside its dispatch branch would
/// stop reading inbound frames while blocked; the server's send buffer would
/// then fill, the server would stop reading requests, and the write would never
/// complete. Here the peer stops reading mid-frame, and the actor still routes
/// a reply and still lapses a request behind the stall.
#[tokio::test(start_paused = true)]
async fn a_blocked_write_stops_neither_replies_nor_timers() {
    let timeouts = Timeouts::default();
    let (connection, mut peer) = buffered_pair(4, timeouts, 1_024);

    let answered = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(tagged(1)).await }
    });
    let first = mid_of(&peer.frame().await);

    let stalled = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(tagged(2)).await }
    });
    // Far larger than the socket will take, and the peer is not reading.
    let huge = tokio::spawn({
        let connection = connection.clone();
        async move {
            connection
                .request(Request::new(ECHO, 0xFFFF, 0, vec![7; 16_384]))
                .await
        }
    });
    tokio::time::advance(Duration::from_millis(1)).await;

    // The actor is blocked on a write it cannot finish, and still reads.
    peer.send(&Fragment::new(first, 4).at(0, vec![1; 4]).encode())
        .await;
    assert_eq!(
        answered
            .await
            .unwrap()
            .unwrap()
            .transaction()
            .unwrap()
            .data(),
        &[1; 4]
    );

    // And still fires timers.
    let start = tokio::time::Instant::now();
    tokio::time::advance(timeouts.per_request + Duration::from_secs(1)).await;
    assert!(matches!(stalled.await.unwrap(), Err(Error::Timeout)));
    assert!(
        start.elapsed() < timeouts.per_request + Duration::from_secs(5),
        "the timer did not fire behind the stalled write: {:?}",
        start.elapsed()
    );

    // Dispatch commits at the first byte: the frame goes out whole even though
    // the request that carries it has lapsed in the meantime.
    let mut seen = 0usize;
    loop {
        let frame = peer.frame().await;
        seen += frame.len();
        if command_of(&frame) == ECHO {
            assert_eq!(frame.len(), HEADER_LEN + 16_384);
            break;
        }
    }
    assert!(seen > 16_384);
    huge.abort();
    let _ = huge.await;
}

/// The actor takes a waiting close before a waiting request. Closes and
/// requests arrive on two different channels, and an unbiased `select` between
/// two ready channels chooses arbitrarily.
#[tokio::test(start_paused = true)]
async fn a_waiting_close_reaches_the_wire_ahead_of_a_waiting_request() {
    let (connection, mut peer) = pair(1, Timeouts::default());
    let holding = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(echo()).await }
    });
    let held = mid_of(&peer.frame().await);

    connection.enqueue_close(Request::new(CLOSE, 1, 1, vec![3, 0, 0, 0, 0, 0, 0, 0, 0]));
    let operation = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(echo()).await }
    });
    assert!(peer.next_frame().await.is_none());

    peer.send(&bodyless(ECHO, NtStatus::SUCCESS, held)).await;
    let next = peer.frame().await;
    assert_eq!(
        command_of(&next),
        CLOSE,
        "the close goes out ahead of the operation issued after it"
    );

    peer.send(&bodyless(CLOSE, NtStatus::SUCCESS, mid_of(&next)))
        .await;
    assert_eq!(command_of(&peer.frame().await), ECHO);
    let _ = holding.await;
    operation.abort();
    let _ = operation.await;
}

/// Eight closes in a row and no more. A task dropping handles in a loop keeps
/// the close queue non-empty, and a loop rule that drained it first without
/// limit would hold every other task's requests off the wire indefinitely.
#[tokio::test(start_paused = true)]
async fn eight_closes_in_a_row_do_not_starve_a_request() {
    let (connection, mut peer) = pair(1, Timeouts::default());
    let holding = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(echo()).await }
    });
    let held = mid_of(&peer.frame().await);

    for _ in 0..12 {
        connection.enqueue_close(Request::new(CLOSE, 1, 1, vec![3, 0, 0, 0, 0, 0, 0, 0, 0]));
    }
    let operation = tokio::spawn({
        let connection = connection.clone();
        async move { connection.request(echo()).await }
    });
    assert!(peer.next_frame().await.is_none());
    peer.send(&bodyless(ECHO, NtStatus::SUCCESS, held)).await;

    let mut commands = Vec::new();
    for _ in 0..9 {
        let frame = peer.frame().await;
        commands.push(command_of(&frame));
        peer.send(&bodyless(
            command_of(&frame),
            NtStatus::SUCCESS,
            mid_of(&frame),
        ))
        .await;
    }
    assert_eq!(
        commands,
        [CLOSE; 8].into_iter().chain([ECHO]).collect::<Vec<_>>()
    );

    let _ = holding.await;
    let _ = operation.await;
}

/// The connection fails once the retirement budget is spent. A server that
/// accepts requests and answers none of them properly is one this client should
/// stop talking to; failing is the ordinary teardown, so the cache re-dials on
/// the next call.
#[tokio::test(start_paused = true)]
async fn the_retirement_budget_fails_the_connection() {
    let (connection, mut peer) = pair(4, Timeouts::default());
    let mut retired = 0usize;
    loop {
        let issuer = tokio::spawn({
            let connection = connection.clone();
            async move { connection.request(tagged(1)).await }
        });
        let Some(frame) = peer.next_frame().await else {
            break;
        };
        // More than the request asked for: a protocol error that ends the
        // request and retires its multiplex id.
        peer.send(
            &Fragment::new(mid_of(&frame), 65_473)
                .at(0, vec![0; 8])
                .encode(),
        )
        .await;
        match issuer.await.unwrap() {
            Err(Error::Reassembly(_)) => retired += 1,
            Err(Error::Lost) => break,
            other => panic!("unexpected outcome: {other:?}"),
        }
    }
    assert_eq!(
        retired, 1_024,
        "the 1,024th retirement fails the connection"
    );
    assert!(peer.ended().await);
}
