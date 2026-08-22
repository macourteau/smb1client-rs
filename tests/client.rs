//! The connection and tree caches, over a dialer that hands back a duplex
//! stream instead of a socket.
//!
//! **What a test replaces here is the stream, not the sequence.** Every
//! connection below runs the real handshake, the real actor and the real
//! teardown; the only thing the tests supply is what the bytes travel over and
//! what the server on the far end says. Three of the properties this file
//! proves are timing properties — the idle probe at one overall deadline, the
//! eviction sweep at twenty, and the goodbye being awaited — and none of them
//! is reachable in real time, so the suite runs under tokio's virtual clock.
//!
//! Each test says what a plausible wrong implementation does, because that is
//! what says whether the test is worth having.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::{Notify, Semaphore};
use tokio::task::JoinHandle;

use smb1client::client::{Client, ClientConfig, Dialer, Stream};
use smb1client::{Credentials, Error, NtStatus, Server, Tree, UncPath};

const HEADER_LEN: usize = 32;

const CLOSE: u8 = 0x04;
const ECHO: u8 = 0x2B;
const READ_ANDX: u8 = 0x2E;
const TRANSACTION2: u8 = 0x32;
const TREE_DISCONNECT: u8 = 0x71;
const NEGOTIATE: u8 = 0x72;
const SESSION_SETUP_ANDX: u8 = 0x73;
const LOGOFF_ANDX: u8 = 0x74;
const TREE_CONNECT_ANDX: u8 = 0x75;
const NT_CREATE_ANDX: u8 = 0xA2;

/// The user id every scripted session setup assigns.
const UID: u16 = 0x1234;

/// What the Samba container advertises, which meets the handshake's floor.
const SAMBA_CAPABILITIES: u32 = 0x8080_F3FD;

/// `NEGOTIATE_USER_SECURITY | NEGOTIATE_ENCRYPT_PASSWORDS`.
const SECURITY_MODE: u8 = 0x03;

/// The [MS-NLMP] 4.2.4.3 CHALLENGE_MESSAGE, which is a real one and belongs to
/// nobody.
const SPEC_CHALLENGE: &str = "4e544c4d53535000020000000c000c003800000033828ae20123456789abcdef\
0000000000000000240024004400000006007017 0000000f5300650072007600650072000\
2000c0044006f006d00610069006e0001000c00530065007200760065007200 00000000";

// ===========================================================================
// The scripted server.
// ===========================================================================

/// What the server does with a command a test is steering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum Reaction {
    /// Answer it.
    #[default]
    Answer,
    /// Read it and say nothing, which is a server that has stopped speaking
    /// without closing the socket.
    Ignore,
    /// Drop the connection, which is what a silent hang-up looks like.
    HangUp,
}

/// How the scripted servers behave. Every connection reads the same rules, and
/// a test changes them between calls.
struct Rules {
    echo: Reaction,
    read: Reaction,
    /// The status a TRANS2 is refused with, where one is.
    trans2_status: Option<NtStatus>,
    /// The status a logoff is answered with.
    logoff_status: NtStatus,
    /// Whether a logoff waits to be released before it is answered.
    hold_logoff: bool,
}

impl Default for Rules {
    fn default() -> Self {
        Self {
            echo: Reaction::Answer,
            read: Reaction::Answer,
            trans2_status: None,
            logoff_status: NtStatus::SUCCESS,
            hold_logoff: false,
        }
    }
}

/// The servers a test dials, and everything they saw.
struct Fixture {
    rules: Mutex<Rules>,
    /// Every dial attempted, in order, failures included.
    dials: Mutex<Vec<Server>>,
    /// How many of the next dials fail before they reach a server.
    failing: Mutex<usize>,
    /// Held closed while a test wants dials to be in flight.
    gate: Semaphore,
    gated: AtomicBool,
    /// Every frame a server read, tagged with the connection it arrived on.
    log: Mutex<Vec<(usize, Vec<u8>)>>,
    /// Whether each connection's server has ended.
    ended: Mutex<Vec<Arc<AtomicBool>>>,
    servers: Mutex<Vec<JoinHandle<()>>>,
    /// Released by a test that is proving the logoff is awaited.
    logoff: Notify,
}

impl Fixture {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            rules: Mutex::new(Rules::default()),
            dials: Mutex::new(Vec::new()),
            failing: Mutex::new(0),
            gate: Semaphore::new(0),
            gated: AtomicBool::new(false),
            log: Mutex::new(Vec::new()),
            ended: Mutex::new(Vec::new()),
            servers: Mutex::new(Vec::new()),
            logoff: Notify::new(),
        })
    }

    fn dialer(self: &Arc<Self>) -> Dialer {
        let fixture = Arc::clone(self);
        Arc::new(move |server: Server| {
            let fixture = Arc::clone(&fixture);
            Box::pin(async move { fixture.dial(server).await })
        })
    }

    async fn dial(self: Arc<Self>, server: Server) -> smb1client::Result<Box<dyn Stream>> {
        let index = {
            let mut dials = guard(&self.dials);
            dials.push(server);
            dials.len() - 1
        };
        if self.gated.load(Ordering::SeqCst) {
            let permit = self.gate.acquire().await.expect("the gate is never closed");
            permit.forget();
        }
        {
            let mut failing = guard(&self.failing);
            if *failing > 0 {
                *failing -= 1;
                return Err(Error::Io(std::io::Error::other("no route to the server")));
            }
        }

        let (client, server) = tokio::io::duplex(256 * 1024);
        let ended = Arc::new(AtomicBool::new(false));
        guard(&self.ended).push(Arc::clone(&ended));
        let fixture = Arc::clone(&self);
        let handle = tokio::spawn(async move {
            serve(server, fixture, index).await;
            ended.store(true, Ordering::SeqCst);
        });
        guard(&self.servers).push(handle);
        Ok(Box::new(client))
    }

    /// How many dials have been attempted, failures included.
    fn dials(&self) -> usize {
        guard(&self.dials).len()
    }

    /// Makes the next `count` dials fail before they reach a server.
    fn fail_dials(&self, count: usize) {
        *guard(&self.failing) = count;
    }

    /// Holds every dial from here until it is released.
    fn hold_dials(&self) {
        self.gated.store(true, Ordering::SeqCst);
    }

    fn release_dials(&self, count: usize) {
        self.gate.add_permits(count);
    }

    fn rules(&self) -> MutexGuard<'_, Rules> {
        guard(&self.rules)
    }

    /// Every frame of one command, over every connection.
    fn frames(&self, command: u8) -> Vec<Vec<u8>> {
        guard(&self.log)
            .iter()
            .filter(|(_, frame)| frame[4] == command)
            .map(|(_, frame)| frame.clone())
            .collect()
    }

    fn count(&self, command: u8) -> usize {
        self.frames(command).len()
    }

    /// The commands one connection saw, in order.
    fn commands_on(&self, connection: usize) -> Vec<u8> {
        guard(&self.log)
            .iter()
            .filter(|(index, _)| *index == connection)
            .map(|(_, frame)| frame[4])
            .collect()
    }

    /// Drops the far end of one connection, which is a server vanishing with no
    /// FIN of its own that the client asked for.
    fn hang_up(&self, connection: usize) {
        guard(&self.servers)[connection].abort();
    }

    fn server_ended(&self, connection: usize) -> bool {
        guard(&self.ended)
            .get(connection)
            .is_some_and(|ended| ended.load(Ordering::SeqCst))
    }
}

/// One scripted server, for the life of one connection.
async fn serve(mut stream: DuplexStream, fixture: Arc<Fixture>, index: usize) {
    let mut setups = 0;
    let mut next_tid = 1u16;
    loop {
        let Some(frame) = read_message(&mut stream).await else {
            return;
        };
        let command = frame[4];
        let mid = mid_of(&frame);
        guard(&fixture.log).push((index, frame.clone()));

        let reply = match command {
            NEGOTIATE => negotiate_response(mid),
            SESSION_SETUP_ANDX => {
                setups += 1;
                if setups == 1 {
                    setup_response(NtStatus::MORE_PROCESSING_REQUIRED, &challenge_token(), mid)
                } else {
                    setup_response(NtStatus::SUCCESS, &[], mid)
                }
            }
            ECHO => match fixture.rules().echo {
                Reaction::Answer => echo_response(mid),
                Reaction::Ignore => continue,
                Reaction::HangUp => return,
            },
            READ_ANDX => match fixture.rules().read {
                Reaction::Answer => read_response(mid, &[]),
                Reaction::Ignore => continue,
                Reaction::HangUp => return,
            },
            TREE_CONNECT_ANDX => {
                let tid = next_tid;
                next_tid += 1;
                tree_connect_response(mid, tid, service_of(&frame))
            }
            TRANSACTION2 => {
                let status = fixture.rules().trans2_status;
                match status {
                    // Every TRANS2 a test drives is one it wants refused; the
                    // successful paths are covered where the verbs are.
                    Some(status) => bodyless(TRANSACTION2, status, mid),
                    None => bodyless(TRANSACTION2, NtStatus::SUCCESS, mid),
                }
            }
            NT_CREATE_ANDX => create_response(mid),
            LOGOFF_ANDX => {
                let (hold, status) = {
                    let rules = fixture.rules();
                    (rules.hold_logoff, rules.logoff_status)
                };
                if hold {
                    fixture.logoff.notified().await;
                }
                logoff_response(status, mid)
            }
            CLOSE | TREE_DISCONNECT => bodyless(command, NtStatus::SUCCESS, mid),
            other => bodyless(other, NtStatus::SUCCESS, mid),
        };
        if stream.write_all(&framed(&reply)).await.is_err() {
            return;
        }
    }
}

// ===========================================================================
// Frames.
// ===========================================================================

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

async fn read_message(stream: &mut DuplexStream) -> Option<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.ok()?;
    let length = (usize::from(header[1] & 0x01) << 16)
        | usize::from(u16::from_be_bytes([header[2], header[3]]));
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.ok()?;
    Some(body)
}

fn header(command: u8, status: NtStatus, tid: u16, uid: u16, mid: u16) -> Vec<u8> {
    let mut header = Vec::with_capacity(HEADER_LEN);
    header.extend_from_slice(b"\xffSMB");
    header.push(command);
    header.extend_from_slice(&status.code().to_le_bytes());
    header.push(0x98);
    header.extend_from_slice(&0xC803u16.to_le_bytes());
    header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&[0u8; 8]);
    header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&tid.to_le_bytes());
    header.extend_from_slice(&1u16.to_le_bytes());
    header.extend_from_slice(&uid.to_le_bytes());
    header.extend_from_slice(&mid.to_le_bytes());
    header
}

fn body(words: &[u8], area: &[u8]) -> Vec<u8> {
    let mut out = vec![(words.len() / 2) as u8];
    out.extend_from_slice(words);
    out.extend_from_slice(&(area.len() as u16).to_le_bytes());
    out.extend_from_slice(area);
    out
}

fn message(
    command: u8,
    status: NtStatus,
    tid: u16,
    mid: u16,
    words: &[u8],
    area: &[u8],
) -> Vec<u8> {
    let mut out = header(command, status, tid, UID, mid);
    out.extend_from_slice(&body(words, area));
    out
}

fn bodyless(command: u8, status: NtStatus, mid: u16) -> Vec<u8> {
    message(command, status, 0, mid, &[], &[])
}

fn words(values: &[u16]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

fn negotiate_response(mid: u16) -> Vec<u8> {
    let mut block = Vec::new();
    block.extend_from_slice(&0u16.to_le_bytes()); // DialectIndex
    block.push(SECURITY_MODE);
    block.extend_from_slice(&50u16.to_le_bytes()); // MaxMpxCount
    block.extend_from_slice(&1u16.to_le_bytes()); // MaxNumberVcs
    block.extend_from_slice(&65_535u32.to_le_bytes()); // MaxBufferSize
    block.extend_from_slice(&65_536u32.to_le_bytes()); // MaxRawSize
    block.extend_from_slice(&0x0DFFu32.to_le_bytes()); // SessionKey
    block.extend_from_slice(&SAMBA_CAPABILITIES.to_le_bytes());
    block.extend_from_slice(&0i64.to_le_bytes()); // SystemTime
    block.extend_from_slice(&0i16.to_le_bytes()); // ServerTimeZone
    block.push(0); // ChallengeLength
    assert_eq!(block.len(), 34);

    let mut area = vec![0xAA; 16];
    area.extend_from_slice(&[0x60, 0x00]);
    message(NEGOTIATE, NtStatus::SUCCESS, 0, mid, &block, &area)
}

/// A DER `NegTokenResp` carrying an NTLM CHALLENGE.
fn challenge_token() -> Vec<u8> {
    let challenge = hex::decode(SPEC_CHALLENGE.replace([' ', '\n'], "")).expect("valid hex");
    let mut token = vec![0x04];
    token.push(challenge.len() as u8);
    token.extend_from_slice(&challenge);
    let mut response = vec![0xA2, token.len() as u8];
    response.extend_from_slice(&token);
    let mut sequence = vec![0x30, response.len() as u8];
    sequence.extend_from_slice(&response);
    let mut out = vec![0xA1, sequence.len() as u8];
    out.extend_from_slice(&sequence);
    out
}

fn setup_response(status: NtStatus, blob: &[u8], mid: u16) -> Vec<u8> {
    let mut block = vec![0xFF, 0x00];
    block.extend_from_slice(&0u16.to_le_bytes()); // AndXOffset
    block.extend_from_slice(&0u16.to_le_bytes()); // Action: not a guest
    block.extend_from_slice(&(blob.len() as u16).to_le_bytes());

    let mut area = blob.to_vec();
    // The byte area begins at 43, so the strings need a pad wherever the blob
    // leaves them on an odd offset.
    if !(43 + blob.len()).is_multiple_of(2) {
        area.push(0);
    }
    for text in ["Scripted", "smb1client-tests", "WORKGROUP"] {
        area.extend(text.encode_utf16().flat_map(u16::to_le_bytes));
        area.extend_from_slice(&[0, 0]);
    }
    message(SESSION_SETUP_ANDX, status, 0, mid, &block, &area)
}

/// The service string a tree connect asked for, which is the last field of its
/// byte area.
fn service_of(frame: &[u8]) -> String {
    let area_at = HEADER_LEN + 1 + usize::from(frame[HEADER_LEN]) * 2 + 2;
    let area = &frame[area_at..];
    let service = area
        .rsplit(|&byte| byte == 0)
        .find(|part| !part.is_empty())
        .unwrap_or_default();
    String::from_utf8_lossy(service).into_owned()
}

fn tree_connect_response(mid: u16, tid: u16, service: String) -> Vec<u8> {
    let block = vec![0xFF, 0x00, 0x00, 0x00, 0x00, 0x00];
    let mut area = service.into_bytes();
    area.push(0);
    // The filesystem name is Unicode and starts on a word boundary, which the
    // server reaches by padding when the ASCII service before it left an odd
    // offset. The byte area itself begins at 41.
    if !(41 + area.len()).is_multiple_of(2) {
        area.push(0);
    }
    area.extend("NTFS".encode_utf16().flat_map(u16::to_le_bytes));
    area.extend_from_slice(&[0, 0]);
    message(
        TREE_CONNECT_ANDX,
        NtStatus::SUCCESS,
        tid,
        mid,
        &block,
        &area,
    )
}

fn echo_response(mid: u16) -> Vec<u8> {
    message(ECHO, NtStatus::SUCCESS, 0, mid, &words(&[0]), &[])
}

fn logoff_response(status: NtStatus, mid: u16) -> Vec<u8> {
    message(LOGOFF_ANDX, status, 0, mid, &[0xFF, 0x00, 0x00, 0x00], &[])
}

fn create_response(mid: u16) -> Vec<u8> {
    let mut block = Vec::new();
    block.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00]);
    block.push(0); // OplockLevel
    block.extend_from_slice(&7u16.to_le_bytes()); // Fid
    block.extend_from_slice(&1u32.to_le_bytes()); // CreateAction
    for _ in 0..4 {
        block.extend_from_slice(&0i64.to_le_bytes());
    }
    block.extend_from_slice(&0x80u32.to_le_bytes()); // ExtFileAttributes
    block.extend_from_slice(&0u64.to_le_bytes()); // AllocationSize
    block.extend_from_slice(&0u64.to_le_bytes()); // EndOfFile
    block.extend_from_slice(&0u16.to_le_bytes()); // ResourceType
    block.extend_from_slice(&0u16.to_le_bytes()); // NMPipeStatus
    block.push(0); // Directory
    assert_eq!(block.len(), 34 * 2);
    message(NT_CREATE_ANDX, NtStatus::SUCCESS, 0, mid, &block, &[])
}

fn read_response(mid: u16, data: &[u8]) -> Vec<u8> {
    let word_count = 12usize;
    let data_offset = HEADER_LEN + 1 + word_count * 2 + 2;
    let mut block = Vec::new();
    block.extend_from_slice(&[0xFF, 0x00, 0x00, 0x00]);
    block.extend_from_slice(&words(&[
        0xFFFF,
        0,
        0,
        data.len() as u16,
        data_offset as u16,
        (data.len() >> 16) as u16,
        0,
        0,
        0,
        0,
    ]));
    message(READ_ANDX, NtStatus::SUCCESS, 0, mid, &block, data)
}

fn mid_of(frame: &[u8]) -> u16 {
    u16::from_le_bytes([frame[30], frame[31]])
}

fn tid_of(frame: &[u8]) -> u16 {
    u16::from_le_bytes([frame[24], frame[25]])
}

fn uid_of(frame: &[u8]) -> u16 {
    u16::from_le_bytes([frame[28], frame[29]])
}

// ===========================================================================
// Driving.
// ===========================================================================

fn guard<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn config() -> ClientConfig {
    ClientConfig::new(Credentials::new("smbtest", "smbtest"))
}

fn client(fixture: &Arc<Fixture>) -> Client {
    Client::with_dialer(config(), fixture.dialer())
}

fn path(server: &str, share: &str) -> UncPath {
    format!(r"\\{server}\{share}")
        .parse()
        .expect("a valid UNC path")
}

/// Lets every other task run until `ready` holds, without letting the clock
/// move: the runtime has work while this is spinning, so nothing auto-advances
/// under it.
async fn until(what: &str, ready: impl Fn() -> bool) {
    for _ in 0..10_000 {
        if ready() {
            return;
        }
        tokio::task::yield_now().await;
    }
    panic!("{what} never happened");
}

/// Lets everything that can run, run.
async fn settle() {
    for _ in 0..64 {
        tokio::task::yield_now().await;
    }
}

/// The verb the tests drive a refusal through: one TRANS2, whose reply the
/// scripted server refuses with whatever status the rules carry.
async fn metadata(tree: &Tree) -> Result<(), Error> {
    tree.metadata("file.txt").await.map(|_| ())
}

// ===========================================================================
// Keying.
// ===========================================================================

/// **What a wrong implementation does**: keys the cache on the host alone and
/// hands the second path the first path's connection — which is the exact shape
/// of this campaign's own acceptance container, a second SMB1 server on
/// `127.0.0.1:10445` beside whatever answers on 445.
#[tokio::test(start_paused = true)]
async fn two_ports_on_one_host_are_two_servers() {
    let fixture = Fixture::new();
    let client = client(&fixture);

    client
        .tree(&path("127.0.0.1", "share"))
        .await
        .expect("the first server answers");
    client
        .tree(&path("127.0.0.1:10445", "share"))
        .await
        .expect("the second server answers");

    assert_eq!(fixture.dials(), 2, "a port is part of the cache key");
}

/// **What a wrong implementation does**: keys on the `Server` value, or on the
/// path, and dials twice for one server because the caller wrote its name in a
/// different case — or keys on the whole UNC path and dials again for a second
/// share.
#[tokio::test(start_paused = true)]
async fn one_server_is_one_connection_however_it_is_spelled() {
    let fixture = Fixture::new();
    let client = client(&fixture);

    client.tree(&path("Server", "share")).await.expect("a tree");
    client.tree(&path("server", "share")).await.expect("a tree");
    client.tree(&path("SERVER", "other")).await.expect("a tree");

    assert_eq!(fixture.dials(), 1, "the host half of the key is lowercased");
    assert_eq!(
        fixture.count(TREE_CONNECT_ANDX),
        2,
        "two shares are two trees on the one connection"
    );
}

/// **What a wrong implementation does**: connects the tree afresh on every
/// call, spending a round trip and a server-side handle each time — and hands
/// back handles that a `Tree::close` on any one of them would invalidate.
#[tokio::test(start_paused = true)]
async fn one_share_asked_for_twice_is_one_tree_connect() {
    let fixture = Fixture::new();
    let client = client(&fixture);

    let first = client.tree(&path("server", "share")).await.expect("a tree");
    let second = client.tree(&path("server", "share")).await.expect("a tree");

    assert_eq!(fixture.count(TREE_CONNECT_ANDX), 1);
    assert_eq!(first.tid(), second.tid());
}

/// The host reaches the wire as the caller wrote it: the lowercasing belongs to
/// the cache key alone, and no request carries that key.
///
/// **What a wrong implementation does**: normalises once, at the front door, so
/// the tree connect names `\\server\share` for a caller who wrote `Server` —
/// and, on the `IPC$` path, hands a server a name it may not recognise.
#[tokio::test(start_paused = true)]
async fn the_host_goes_on_the_wire_as_the_caller_wrote_it() {
    let fixture = Fixture::new();
    let client = client(&fixture);

    client.tree(&path("Server", "share")).await.expect("a tree");

    let connect = fixture.frames(TREE_CONNECT_ANDX);
    let name: String = String::from_utf16_lossy(
        &connect[0][HEADER_LEN..]
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&pair| u16::from_le_bytes(pair))
            .collect::<Vec<_>>(),
    );
    assert!(
        name.contains(r"\\Server\share"),
        "the tree connect carries the host as written: {name:?}"
    );
}

// ===========================================================================
// Single-flight dialling.
// ===========================================================================

/// **What a wrong implementation does**: releases the cache lock before the
/// dial completes — the shape smb-rs carries a `// TODO: This is a bit racy`
/// against — so every task that met the cold cache dials, authenticates and
/// caches a connection of its own, and all but the last are leaked until
/// something drops them.
#[tokio::test(start_paused = true)]
async fn several_tasks_meeting_a_cold_cache_produce_one_dial() {
    let fixture = Fixture::new();
    fixture.hold_dials();
    let client = Arc::new(client(&fixture));

    let racers: Vec<_> = (0..4)
        .map(|_| {
            let client = Arc::clone(&client);
            tokio::spawn(async move { client.tree(&path("server", "share")).await.is_ok() })
        })
        .collect();

    until("a dial to start", || fixture.dials() == 1).await;
    settle().await;
    assert_eq!(fixture.dials(), 1, "one dial, however many tasks want it");

    fixture.release_dials(4);
    for racer in racers {
        assert!(racer.await.expect("the task did not panic"));
    }
    assert_eq!(fixture.dials(), 1);
}

/// **What a wrong implementation does**: runs the dial inside the waiting
/// task's own future, so the last waiter dropping cancels it. The next call
/// then dials again — the expensive half of the work thrown away exactly when a
/// caller has shown it is wanted.
#[tokio::test(start_paused = true)]
async fn a_dial_in_flight_runs_to_completion_when_its_last_waiter_drops() {
    let fixture = Fixture::new();
    fixture.hold_dials();
    let client = Arc::new(client(&fixture));

    let abandoned = {
        let client = Arc::clone(&client);
        tokio::spawn(async move { client.tree(&path("server", "share")).await.map(|_| ()) })
    };
    until("a dial to start", || fixture.dials() == 1).await;
    abandoned.abort();
    let _ = abandoned.await;

    // Nobody is waiting for this connection any more, and it is finished and
    // cached regardless.
    fixture.release_dials(1);
    until("the handshake to finish", || {
        fixture.count(SESSION_SETUP_ANDX) == 2
    })
    .await;

    client
        .tree(&path("server", "share"))
        .await
        .expect("the connection nobody waited for is there");
    assert_eq!(fixture.dials(), 1, "the abandoned dial was not thrown away");
}

/// **What a wrong implementation does**: caches the failure, so a server that
/// was briefly unreachable stays unreachable to this client for ever; or leaves
/// the in-flight marker in the map, which strands every later caller waiting on
/// a dial that has already finished.
#[tokio::test(start_paused = true)]
async fn a_dial_that_fails_is_not_cached() {
    let fixture = Fixture::new();
    fixture.fail_dials(1);
    let client = client(&fixture);

    let refused = client.tree(&path("server", "share")).await;
    assert!(matches!(refused, Err(Error::Io(_))), "{refused:?}");

    client
        .tree(&path("server", "share"))
        .await
        .expect("the next call dials afresh");
    assert_eq!(fixture.dials(), 2);
}

/// A dial has one failure to report and however many tasks waiting on it.
///
/// **What a wrong implementation does**: hands the waiters an `Ok` they cannot
/// use, or leaves them waiting on a signal the failed dial never sends.
#[tokio::test(start_paused = true)]
async fn every_task_waiting_on_a_failed_dial_is_told() {
    let fixture = Fixture::new();
    fixture.hold_dials();
    fixture.fail_dials(1);
    let client = Arc::new(client(&fixture));

    let waiters: Vec<_> = (0..3)
        .map(|_| {
            let client = Arc::clone(&client);
            tokio::spawn(async move {
                client
                    .tree(&path("server", "share"))
                    .await
                    .map(|_| ())
                    .map_err(|error| error.kind())
            })
        })
        .collect();
    until("a dial to start", || fixture.dials() == 1).await;
    fixture.release_dials(1);

    for waiter in waiters {
        let outcome = waiter.await.expect("the task did not panic");
        assert_eq!(
            outcome,
            Err(std::io::ErrorKind::Other),
            "every waiter is told the dial failed, with the failure's own kind"
        );
    }
    assert_eq!(fixture.dials(), 1);
}

// ===========================================================================
// Liveness, the probe and re-dialling.
// ===========================================================================

/// **What a wrong implementation does**: hands the dead connection out for ever
/// — smb-rs's own shape, where `Connection::connect` refuses to reconnect and
/// recovery means discarding the whole client. Windows reaps an idle SMB
/// session after fifteen minutes by default, so this needs no network fault to
/// happen.
#[tokio::test(start_paused = true)]
async fn a_connection_that_died_is_evicted_and_the_next_call_re_dials() {
    let fixture = Fixture::new();
    let client = client(&fixture);
    let tree = client.tree(&path("server", "share")).await.expect("a tree");

    fixture.hang_up(0);
    let lost = metadata(&tree).await;
    assert!(
        matches!(lost, Err(Error::ConnectionLost { .. })),
        "the in-flight call fails rather than being retried: {lost:?}"
    );

    client
        .tree(&path("server", "share"))
        .await
        .expect("the next call re-dials");
    assert_eq!(fixture.dials(), 2);
}

/// The probe, and everything the design fixes about the frame it sends.
///
/// **What a wrong implementation does**: never probes, and charges the next
/// caller a full deadline against a socket that died while nobody was
/// watching; or sends the echo under the session's own `UID` and `TID`, which
/// asks a question about the session when the question is about the transport;
/// or asks for more than one reply, in which case every reply after the first
/// arrives on an id the table no longer holds and fails the connection the
/// probe exists to vouch for.
#[tokio::test(start_paused = true)]
async fn a_connection_idle_past_one_deadline_is_probed_before_it_is_reused() {
    let fixture = Fixture::new();
    let client = client(&fixture);
    client.tree(&path("server", "share")).await.expect("a tree");

    tokio::time::advance(config().overall_deadline + Duration::from_secs(1)).await;
    client
        .tree(&path("server", "other"))
        .await
        .expect("the probe answered");

    let probes = fixture.frames(ECHO);
    assert_eq!(
        probes.len(),
        1,
        "one probe, on the first use after the idle"
    );
    let probe = &probes[0];
    assert_eq!(tid_of(probe), 0xFFFF, "TID says no tree");
    assert_eq!(uid_of(probe), 0, "UID says no session");
    assert_eq!(probe[HEADER_LEN], 1, "WordCount");
    assert_eq!(
        &probe[HEADER_LEN + 1..],
        &[0x01, 0x00, 0x00, 0x00],
        "EchoCount = 1 and an empty byte area"
    );
    assert_eq!(
        fixture.dials(),
        1,
        "the probe answered, so nothing re-dials"
    );
}

/// **What a wrong implementation does**: probes on every reuse, which puts a
/// round trip in front of every call a consumer makes.
#[tokio::test(start_paused = true)]
async fn a_connection_idle_under_one_deadline_is_not_probed() {
    let fixture = Fixture::new();
    let client = client(&fixture);
    client.tree(&path("server", "share")).await.expect("a tree");

    tokio::time::advance(config().overall_deadline / 2).await;
    client.tree(&path("server", "other")).await.expect("a tree");

    assert_eq!(fixture.count(ECHO), 0);
}

/// **What a wrong implementation does**: returns the probe's failure to the
/// caller, which turns the one thing the probe was for — noticing a silent drop
/// before the caller pays for it — into the caller paying for it anyway.
#[tokio::test(start_paused = true)]
async fn a_probe_that_fails_evicts_and_the_call_re_dials() {
    let fixture = Fixture::new();
    let client = client(&fixture);
    client.tree(&path("server", "share")).await.expect("a tree");
    fixture.rules().echo = Reaction::HangUp;

    tokio::time::advance(config().overall_deadline + Duration::from_secs(1)).await;
    let tree = client
        .tree(&path("server", "share"))
        .await
        .expect("the call re-dials rather than failing");

    assert_eq!(fixture.dials(), 2);
    assert_eq!(tree.tid(), 1, "a fresh connection's first tree");
}

/// Two tasks reaching for one long-idle connection at once probe it once.
///
/// **What a wrong implementation does**: reads the idle time without marking
/// the entry used, so every task that arrives in the same instant sends its own
/// echo — and on a server that has genuinely gone, each of them then evicts and
/// dials.
#[tokio::test(start_paused = true)]
async fn concurrent_reuse_of_an_idle_connection_probes_it_once() {
    let fixture = Fixture::new();
    let client = Arc::new(client(&fixture));
    client.tree(&path("server", "share")).await.expect("a tree");

    tokio::time::advance(config().overall_deadline + Duration::from_secs(1)).await;
    let racers: Vec<_> = (0..4)
        .map(|_| {
            let client = Arc::clone(&client);
            tokio::spawn(async move { client.tree(&path("server", "share")).await.is_ok() })
        })
        .collect();
    for racer in racers {
        assert!(racer.await.expect("the task did not panic"));
    }

    assert_eq!(fixture.count(ECHO), 1);
}

// ===========================================================================
// The two statuses that are not the same scope.
// ===========================================================================

/// **What a wrong implementation does**: treats a tree-scoped status as a lost
/// connection and tears down every other tree on it, their open handles and
/// every in-flight request with it — or leaves the discarded tree in the cache,
/// so every later call on that share is refused by a server that has already
/// said the tree is gone.
#[tokio::test(start_paused = true)]
async fn a_discarded_tree_is_re_opened_and_the_connection_is_left_alone() {
    let fixture = Fixture::new();
    let client = client(&fixture);
    let gone = client.tree(&path("server", "share")).await.expect("a tree");
    let other = client.tree(&path("server", "other")).await.expect("a tree");

    fixture.rules().trans2_status = Some(NtStatus::NETWORK_NAME_DELETED);
    let refused = metadata(&gone).await;
    assert!(
        matches!(refused, Err(Error::TreeDisconnected)),
        "{refused:?}"
    );

    // The other tree on the same connection is untouched, and so is the
    // connection: an ordinary open on it still works.
    fixture.rules().trans2_status = None;
    other
        .create_dir("directory")
        .await
        .expect("the other tree is still good");

    let reopened = client
        .tree(&path("server", "share"))
        .await
        .expect("the discarded tree is connected afresh");
    assert_eq!(fixture.dials(), 1, "nothing re-dialled");
    assert_eq!(fixture.count(TREE_CONNECT_ANDX), 3);
    assert_ne!(reopened.tid(), gone.tid());
}

/// **What a wrong implementation does**: treats the session-scoped status as
/// one more refusal and keeps handing out a connection whose session the server
/// has thrown away, so every later call fails and nothing ever re-dials.
#[tokio::test(start_paused = true)]
async fn a_deleted_session_fails_the_connection_and_the_next_call_re_dials() {
    let fixture = Fixture::new();
    let client = client(&fixture);
    let tree = client.tree(&path("server", "share")).await.expect("a tree");

    fixture.rules().trans2_status = Some(NtStatus::USER_SESSION_DELETED);
    let lost = metadata(&tree).await;
    assert!(
        matches!(
            lost,
            Err(Error::ConnectionLost {
                status: Some(NtStatus::USER_SESSION_DELETED)
            })
        ),
        "{lost:?}"
    );

    fixture.rules().trans2_status = None;
    client
        .tree(&path("server", "share"))
        .await
        .expect("the next call re-dials");
    assert_eq!(fixture.dials(), 2);
}

// ===========================================================================
// Idle eviction.
// ===========================================================================

/// **What a wrong implementation does**: sweeps lazily, at cache lookup — which
/// visits exactly the entries eviction does not care about and never the one it
/// does. Nothing in this test touches the cache after the first call, so a lazy
/// sweep evicts nothing and the connection is held for the process's lifetime.
#[tokio::test(start_paused = true)]
async fn a_connection_nobody_comes_back_to_is_evicted_and_says_goodbye() {
    let fixture = Fixture::new();
    let client = client(&fixture);
    let tree = client.tree(&path("server", "share")).await.expect("a tree");
    // The caller's own handle goes; the cache's reference is what is left, and
    // it is what eviction releases.
    drop(tree);

    tokio::time::advance(config().overall_deadline * 21).await;
    until("the eviction", || fixture.count(LOGOFF_ANDX) == 1).await;

    let commands = fixture.commands_on(0);
    let disconnect = commands.iter().position(|&c| c == TREE_DISCONNECT);
    let logoff = commands.iter().position(|&c| c == LOGOFF_ANDX);
    assert!(
        disconnect < logoff,
        "the tree is released before the session: {commands:02x?}"
    );
    until("the socket to close", || fixture.server_ended(0)).await;

    client
        .tree(&path("server", "share"))
        .await
        .expect("the next call dials afresh");
    assert_eq!(fixture.dials(), 2);
}

/// **What a wrong implementation does**: measures idleness from when the
/// connection was dialled rather than from when it was last handed out, and
/// evicts a connection in constant use.
#[tokio::test(start_paused = true)]
async fn an_entry_used_inside_the_window_is_never_evicted() {
    let fixture = Fixture::new();
    let client = client(&fixture);
    client.tree(&path("server", "share")).await.expect("a tree");

    // Ten sweeps' worth of time, with a use inside every eviction window.
    for _ in 0..10 {
        tokio::time::advance(config().overall_deadline * 5).await;
        settle().await;
        client.tree(&path("server", "share")).await.expect("a tree");
    }

    assert_eq!(fixture.dials(), 1, "nothing was evicted");
    assert_eq!(fixture.count(LOGOFF_ANDX), 0);
}

/// The sweeper is a task the client owns, and it ends with the client.
///
/// **What a wrong implementation does**: leaves the timer running against a
/// strong reference of its own, which keeps every cached connection — and its
/// socket — alive for as long as the process runs.
#[tokio::test(start_paused = true)]
async fn dropping_the_client_releases_everything_the_cache_held() {
    let fixture = Fixture::new();
    let client = client(&fixture);
    let tree = client.tree(&path("server", "share")).await.expect("a tree");
    drop(tree);
    drop(client);

    until("the socket to close", || fixture.server_ended(0)).await;
    assert_eq!(
        fixture.count(LOGOFF_ANDX),
        1,
        "a deliberate teardown says goodbye, best-effort where it cannot await"
    );
}

// ===========================================================================
// Shutdown.
// ===========================================================================

/// **What a wrong implementation does**: races the goodbye against the socket
/// close, so `close()` reports success while the server still holds the session
/// — and reporting that release is the whole reason the method is fallible.
#[tokio::test(start_paused = true)]
async fn close_awaits_the_goodbye_rather_than_racing_it() {
    let fixture = Fixture::new();
    let client = client(&fixture);
    client.tree(&path("server", "share")).await.expect("a tree");
    fixture.rules().hold_logoff = true;

    let closing = tokio::spawn(async move { client.close().await });
    until("the logoff to reach the server", || {
        fixture.count(LOGOFF_ANDX) == 1
    })
    .await;
    settle().await;
    assert!(
        !closing.is_finished(),
        "close waits for the logoff it sent to be answered"
    );

    fixture.logoff.notify_one();
    closing
        .await
        .expect("the task did not panic")
        .expect("the goodbye succeeded");
    assert_eq!(fixture.count(TREE_DISCONNECT), 1);
}

/// **What a wrong implementation does**: swallows the failure, or retries it.
/// There is nothing to retry — TCP teardown releases what the server still
/// holds — so the socket closes regardless and the error is what the caller
/// gets.
#[tokio::test(start_paused = true)]
async fn close_reports_a_failed_goodbye_and_closes_anyway() {
    let fixture = Fixture::new();
    let client = client(&fixture);
    client.tree(&path("server", "share")).await.expect("a tree");
    fixture.rules().logoff_status = NtStatus::new(0xC000_0022);

    let refused = client.close().await;
    assert!(matches!(refused, Err(Error::Status(_))), "{refused:?}");
    until("the socket to close", || fixture.server_ended(0)).await;
    assert_eq!(fixture.count(LOGOFF_ANDX), 1, "sent once, not retried");
}

/// **What a wrong implementation does**: sends the session's goodbye anyway,
/// which invalidates the file, listing and tree handles a caller still owns —
/// the one thing shutdown must not do.
#[tokio::test(start_paused = true)]
async fn close_does_not_invalidate_a_tree_the_caller_still_holds() {
    let fixture = Fixture::new();
    let client = client(&fixture);
    let tree = client.tree(&path("server", "share")).await.expect("a tree");

    client.close().await.expect("close succeeds");
    assert_eq!(
        fixture.count(LOGOFF_ANDX),
        0,
        "a handle still holds the connection"
    );
    assert_eq!(fixture.count(TREE_DISCONNECT), 0);
    tree.create_dir("directory")
        .await
        .expect("the caller's own handle still works");

    // And the connection closes when that handle goes, which is what makes the
    // shutdown deterministic without invalidating it.
    drop(tree);
    until("the socket to close", || fixture.server_ended(0)).await;
}

// ===========================================================================
// What the configuration reaches.
// ===========================================================================

/// **What a wrong implementation does**: leaves the adapters on the default
/// four whatever the configuration says, so a consumer holding many adapters at
/// once cannot bound what they hold — the trade the knob exists for.
#[tokio::test(start_paused = true)]
async fn the_configured_read_ahead_reaches_the_adapters() {
    let fixture = Fixture::new();
    let client = Client::with_dialer(
        ClientConfig {
            read_ahead: 2,
            ..config()
        },
        fixture.dialer(),
    );
    let tree = client.tree(&path("server", "share")).await.expect("a tree");
    fixture.rules().read = Reaction::Ignore;

    let file = tree.open("file.txt").await.expect("an open");
    let reading = tokio::spawn(async move {
        use tokio::io::AsyncReadExt;
        let mut reader = file.into_reader();
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await
    });
    until("the reads to be issued", || fixture.count(READ_ANDX) == 2).await;
    settle().await;

    assert_eq!(
        fixture.count(READ_ANDX),
        2,
        "two chunks outstanding, not the default four"
    );
    reading.abort();
}

/// **What a wrong implementation does**: leaves the advertisement at the
/// crate's own default, which is the threshold at which a reply arrives in
/// several messages at all — so the one deliberate way to reach the reassembly
/// path against a live server is unreachable through `Client`.
#[tokio::test(start_paused = true)]
async fn the_configured_buffer_advertisement_reaches_the_session_setup() {
    let fixture = Fixture::new();
    let client = Client::with_dialer(
        ClientConfig {
            advertised_max_buffer_size: 4_500,
            ..config()
        },
        fixture.dialer(),
    );
    client.tree(&path("server", "share")).await.expect("a tree");

    let setup = &fixture.frames(SESSION_SETUP_ANDX)[0];
    let advertised = u16::from_le_bytes([setup[HEADER_LEN + 5], setup[HEADER_LEN + 6]]);
    assert_eq!(advertised, 4_500);
}

/// The other half of the same rule, on the path that cannot await.
///
/// **What a wrong implementation does**: enqueues the session's goodbye from
/// `Drop` whatever else holds the connection, so a client dropped while a
/// caller is still reading a file logs the session off underneath it.
#[tokio::test(start_paused = true)]
async fn dropping_the_client_does_not_log_off_a_connection_a_handle_still_holds() {
    let fixture = Fixture::new();
    let client = client(&fixture);
    let tree = client.tree(&path("server", "share")).await.expect("a tree");

    drop(client);
    settle().await;
    assert_eq!(fixture.count(LOGOFF_ANDX), 0, "a handle still holds it");
    tree.create_dir("directory")
        .await
        .expect("the caller's own handle still works");

    drop(tree);
    until("the socket to close", || fixture.server_ended(0)).await;
}
