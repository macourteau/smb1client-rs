//! The handshake's four refusals, proven over scripted responses on the
//! transport seam.
//!
//! **The acceptance container can produce none of them**, and no fixture can
//! stand in: the capability floor, the `NEGOTIATE_USER_SECURITY` refusal and
//! the `MaxBufferSize` floor all need a negotiate response no tested server
//! sends, and the guest-logon refusal needs an `Action` bit the container is
//! configured never to set. Session-setup frames are excluded from the fixture
//! corpus by rule besides. So the seam is the only place any of the four is
//! reachable, and this is where they are proven.
//!
//! Each test below scripts a server that fails exactly one requirement and
//! passes every other, which is what makes it a test of that requirement rather
//! than of the handshake in general.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

use smb1client::session::MIN_MAX_BUFFER_SIZE;
use smb1client::{Credentials, Error, NtStatus, Session, SessionOptions};

const NEGOTIATE: u8 = 0x72;
const SESSION_SETUP_ANDX: u8 = 0x73;

/// Every capability the floor requires, and the name the error must carry.
const REQUIRED: [(u32, &str); 6] = [
    (0x0000_0010, "CAP_NT_SMBS"),
    (0x0000_0004, "CAP_UNICODE"),
    (0x0000_0008, "CAP_LARGE_FILES"),
    (0x0000_0040, "CAP_STATUS32"),
    (0x0000_0200, "CAP_NT_FIND"),
    (0x8000_0000, "CAP_EXTENDED_SECURITY"),
];

/// What the Samba container advertises, which meets the floor with room over.
const SAMBA_CAPABILITIES: u32 = 0x8080_F3FD;

/// `NEGOTIATE_USER_SECURITY | NEGOTIATE_ENCRYPT_PASSWORDS`, which is what all
/// three tested servers report.
const SECURITY_MODE: u8 = 0x03;

/// The [MS-NLMP] 4.2.4.3 CHALLENGE_MESSAGE, which is a real one and belongs to
/// nobody.
const SPEC_CHALLENGE: &str = "4e544c4d53535000020000000c000c003800000033828ae20123456789abcdef\
0000000000000000240024004400000006007017 0000000f5300650072007600650072000\
2000c0044006f006d00610069006e0001000c00530065007200760065007200 00000000";

/// How a scripted server answers the negotiate.
#[derive(Debug, Clone, Copy)]
struct Negotiate {
    dialect_index: u16,
    security_mode: u8,
    max_buffer_size: u32,
    capabilities: u32,
    nt_status: bool,
}

impl Default for Negotiate {
    fn default() -> Self {
        Self {
            dialect_index: 0,
            security_mode: SECURITY_MODE,
            max_buffer_size: 16_644,
            capabilities: SAMBA_CAPABILITIES,
            nt_status: true,
        }
    }
}

/// How a scripted server answers the session setup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Setup {
    /// A challenge, then success: the two-leg exchange.
    Challenge { guest: bool },
    /// `STATUS_SUCCESS` on the first leg, which issues no challenge and wants no
    /// AUTHENTICATE message. It is precisely the shape a guest downgrade takes.
    ImmediateSuccess { guest: bool },
    /// A refusal.
    Failure(NtStatus),
}

fn header(command: u8, status: NtStatus, uid: u16, mid: u16, nt_status: bool) -> Vec<u8> {
    let mut header = Vec::with_capacity(32);
    header.extend_from_slice(b"\xffSMB");
    header.push(command);
    header.extend_from_slice(&status.code().to_le_bytes());
    header.push(0x98);
    let flags2: u16 = if nt_status { 0xC803 } else { 0x8803 };
    header.extend_from_slice(&flags2.to_le_bytes());
    header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&[0u8; 8]);
    header.extend_from_slice(&0u16.to_le_bytes());
    header.extend_from_slice(&0u16.to_le_bytes());
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

fn negotiate_response(script: Negotiate, mid: u16) -> Vec<u8> {
    let mut words = Vec::new();
    words.extend_from_slice(&script.dialect_index.to_le_bytes());
    words.push(script.security_mode);
    words.extend_from_slice(&50u16.to_le_bytes());
    words.extend_from_slice(&1u16.to_le_bytes());
    words.extend_from_slice(&script.max_buffer_size.to_le_bytes());
    words.extend_from_slice(&65_536u32.to_le_bytes());
    words.extend_from_slice(&0x0DFFu32.to_le_bytes());
    words.extend_from_slice(&script.capabilities.to_le_bytes());
    words.extend_from_slice(&0i64.to_le_bytes());
    words.extend_from_slice(&0i16.to_le_bytes());
    words.push(0);
    assert_eq!(words.len(), 34);

    let mut area = vec![0xAA; 16];
    area.extend_from_slice(&[0x60, 0x00]);
    let mut message = header(NEGOTIATE, NtStatus::SUCCESS, 0, mid, script.nt_status);
    message.extend_from_slice(&body(&words, &area));
    message
}

/// A DER `NegTokenResp` carrying an NTLM CHALLENGE.
fn challenge_token() -> Vec<u8> {
    let challenge = hex::decode(SPEC_CHALLENGE.replace([' ', '\n'], "")).unwrap();
    let mut token = vec![0x04];
    token.push(challenge.len() as u8);
    token.extend_from_slice(&challenge);
    let mut response = vec![0xA2, (token.len()) as u8];
    response.extend_from_slice(&token);
    let mut sequence = vec![0x30, response.len() as u8];
    sequence.extend_from_slice(&response);
    let mut out = vec![0xA1, sequence.len() as u8];
    out.extend_from_slice(&sequence);
    out
}

fn setup_response(status: NtStatus, action: u16, blob: &[u8], uid: u16, mid: u16) -> Vec<u8> {
    let mut words = vec![0xFF, 0x00];
    words.extend_from_slice(&0u16.to_le_bytes());
    words.extend_from_slice(&action.to_le_bytes());
    words.extend_from_slice(&(blob.len() as u16).to_le_bytes());

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

    let mut message = header(SESSION_SETUP_ANDX, status, uid, mid, true);
    message.extend_from_slice(&body(&words, &area));
    message
}

/// Reads one NetBIOS-framed message off the scripted server's end.
async fn read_message(stream: &mut DuplexStream) -> Option<Vec<u8>> {
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await.ok()?;
    let length = (usize::from(header[1] & 0x01) << 16)
        | usize::from(u16::from_be_bytes([header[2], header[3]]));
    let mut body = vec![0u8; length];
    stream.read_exact(&mut body).await.ok()?;
    Some(body)
}

/// Runs a handshake against a scripted server and hands back its result and
/// what the client sent.
async fn handshake(
    negotiate: Negotiate,
    setup: Setup,
    options: SessionOptions,
) -> (Result<Session, Error>, Vec<Vec<u8>>) {
    let (client, mut server) = tokio::io::duplex(64 * 1024);
    // The frames the client sent are collected through a handle the test still
    // holds, because the script outlives no test: once the handshake is done it
    // is blocked on a read nobody will answer.
    let seen: Arc<Mutex<Vec<Vec<u8>>>> = Arc::default();
    let recorder = Arc::clone(&seen);
    let script = tokio::spawn(async move {
        const UID: u16 = 0x1234;
        let record = |frame: Vec<u8>| recorder.lock().expect("no test panics here").push(frame);
        let seen_setups = || {
            recorder
                .lock()
                .expect("no test panics here")
                .iter()
                .filter(|f| f[4] == SESSION_SETUP_ANDX)
                .count()
        };

        let Some(request) = read_message(&mut server).await else {
            return;
        };
        assert_eq!(request[4], NEGOTIATE);
        record(request);
        let reply = negotiate_response(negotiate, 0);
        if server.write_all(&framed(&reply)).await.is_err() {
            return;
        }

        loop {
            let Some(request) = read_message(&mut server).await else {
                return;
            };
            if request[4] != SESSION_SETUP_ANDX {
                record(request);
                continue;
            }
            let first = seen_setups() == 0;
            record(request);
            let reply = match (setup, first) {
                (Setup::Challenge { .. }, true) => setup_response(
                    NtStatus::MORE_PROCESSING_REQUIRED,
                    0,
                    &challenge_token(),
                    UID,
                    0,
                ),
                (Setup::Challenge { guest }, false) => {
                    setup_response(NtStatus::SUCCESS, u16::from(guest), &[], UID, 0)
                }
                (Setup::ImmediateSuccess { guest }, _) => {
                    setup_response(NtStatus::SUCCESS, u16::from(guest), &[], UID, 0)
                }
                (Setup::Failure(status), _) => {
                    let mut message = header(SESSION_SETUP_ANDX, status, 0, 0, true);
                    message.extend_from_slice(&body(&[], &[]));
                    message
                }
            };
            if server.write_all(&framed(&reply)).await.is_err() {
                return;
            }
        }
    });

    let credentials = Credentials::new("smbtest", "smbtest");
    let session = Session::establish(client, &credentials, &options).await;
    // Give the script a moment to record the last frame before it is asked for.
    tokio::time::sleep(Duration::from_millis(20)).await;
    script.abort();
    let frames = seen.lock().expect("no test panics here").clone();
    (session, frames)
}

fn options() -> SessionOptions {
    SessionOptions {
        connect_timeout: Duration::from_secs(5),
        ..SessionOptions::default()
    }
}

/// Refusal 1. **What a wrong implementation does**: checks one capability, or
/// checks the word against a mask that happens to be non-zero, and admits a
/// server missing any of the other five. Dropping each bit in turn is what
/// separates a floor from a spot check — and `CAP_EXTENDED_SECURITY` is the one
/// the design would otherwise assume silently, whose absence would surface
/// inside the SPNEGO decoder instead.
#[tokio::test]
async fn a_server_missing_any_required_capability_is_refused_by_name() {
    for (bit, name) in REQUIRED {
        let negotiate = Negotiate {
            capabilities: SAMBA_CAPABILITIES & !bit,
            ..Negotiate::default()
        };
        let (result, seen) =
            handshake(negotiate, Setup::Challenge { guest: false }, options()).await;
        match result {
            Err(Error::UnsupportedServer(message)) => {
                assert!(
                    message.contains(name),
                    "refusing a server without {name} must say so: {message}"
                );
            }
            other => panic!("{name} missing must be refused, got {other:?}"),
        }
        // And it is refused before any credential reaches the wire.
        assert_eq!(
            seen.iter()
                .filter(|frame| frame[4] == SESSION_SETUP_ANDX)
                .count(),
            0,
            "{name}: the refusal must come before the session setup"
        );
    }

    // The control: the same server with every bit present authenticates.
    let (result, _) = handshake(
        Negotiate::default(),
        Setup::Challenge { guest: false },
        options(),
    )
    .await;
    assert!(result.is_ok(), "{:?}", result.err());
}

/// Refusal 2. **What a wrong implementation does**: reads `SecurityMode` for
/// the encrypt-passwords bit alone — which is what the reference library does,
/// declaring `NEGOTIATE_USER_SECURITY` and never testing it — and proceeds to
/// send a password where a share key is expected.
#[tokio::test]
async fn a_share_level_security_server_is_refused() {
    // `NEGOTIATE_ENCRYPT_PASSWORDS` alone: the bit a check that looked only for
    // encrypted passwords would be satisfied by.
    let negotiate = Negotiate {
        security_mode: 0x02,
        ..Negotiate::default()
    };
    let (result, seen) = handshake(negotiate, Setup::Challenge { guest: false }, options()).await;
    match result {
        Err(Error::UnsupportedServer(message)) => {
            assert!(message.contains("share-level"), "{message}");
        }
        other => panic!("share-level security must be refused, got {other:?}"),
    }
    assert_eq!(
        seen.iter()
            .filter(|frame| frame[4] == SESSION_SETUP_ANDX)
            .count(),
        0,
        "the refusal must come before the password does"
    );
}

/// Refusal 3, and **its location is the load-bearing part**. The chunk-size
/// rules subtract 1,024 from this field as plain arithmetic, which on any value
/// below 1,024 is a debug panic or a release wrap. **What a wrong
/// implementation does**: validates nowhere, or validates at each subtraction
/// with saturating arithmetic, and carries a nonsense buffer size forward with
/// no place that said so.
#[tokio::test]
async fn a_negotiated_buffer_below_the_smb1_minimum_is_refused() {
    let below = Negotiate {
        max_buffer_size: MIN_MAX_BUFFER_SIZE - 1,
        ..Negotiate::default()
    };
    let (result, seen) = handshake(below, Setup::Challenge { guest: false }, options()).await;
    match result {
        Err(Error::UnsupportedServer(message)) => {
            assert!(message.contains("MaxBufferSize"), "{message}");
            assert!(message.contains("4356"), "the floor is named: {message}");
        }
        other => panic!("a buffer below the minimum must be refused, got {other:?}"),
    }
    assert_eq!(
        seen.iter()
            .filter(|frame| frame[4] == SESSION_SETUP_ANDX)
            .count(),
        0
    );

    // The value a subtraction of 1,024 would wrap on, which is the failure the
    // check exists to make impossible.
    let tiny = Negotiate {
        max_buffer_size: 512,
        ..Negotiate::default()
    };
    let (result, _) = handshake(tiny, Setup::Challenge { guest: false }, options()).await;
    assert!(matches!(result, Err(Error::UnsupportedServer(_))));

    // And exactly the floor passes: Windows 11 24H2 advertises this number.
    let at_floor = Negotiate {
        max_buffer_size: MIN_MAX_BUFFER_SIZE,
        ..Negotiate::default()
    };
    let (result, _) = handshake(at_floor, Setup::Challenge { guest: false }, options()).await;
    assert!(result.is_ok(), "{:?}", result.err());
    let session = result.unwrap();
    assert_eq!(session.negotiated().max_buffer_size, MIN_MAX_BUFFER_SIZE);
}

/// Refusal 4, on **both** paths. **What a wrong implementation does**: reads
/// the `Action` bit on the second leg only, and misses it on exactly the
/// exchange where it matters most — a server that answers the first
/// `SESSION_SETUP_ANDX` with `STATUS_SUCCESS` has issued no challenge and
/// checked no password, which is the shape a guest downgrade takes. A second
/// wrong implementation treats a successful status as a successful logon and
/// hands back a session running with whatever rights guests have.
#[tokio::test]
async fn a_guest_logon_is_refused_on_both_paths() {
    for setup in [
        Setup::Challenge { guest: true },
        Setup::ImmediateSuccess { guest: true },
    ] {
        let (result, _) = handshake(Negotiate::default(), setup, options()).await;
        assert!(
            matches!(result, Err(Error::GuestLogon)),
            "{setup:?} must be refused as a guest logon, got {result:?}"
        );

        // Unless the caller asked for it, in which case the session says so.
        let allowed = SessionOptions {
            allow_guest: true,
            ..options()
        };
        let (result, _) = handshake(Negotiate::default(), setup, allowed).await;
        let session = result.expect("guest access the caller asked for is allowed");
        assert!(session.server().guest);
    }

    // And a named logon on either path is not reported as a guest.
    for setup in [
        Setup::Challenge { guest: false },
        Setup::ImmediateSuccess { guest: false },
    ] {
        let (result, _) = handshake(Negotiate::default(), setup, options()).await;
        assert!(!result.expect("a named logon succeeds").server().guest);
    }
}

/// The single-leg exchange sends no AUTHENTICATE message at all.
///
/// **What a wrong implementation does**: waits for a challenge that is never
/// coming, or sends an AUTHENTICATE message the server did not ask for.
#[tokio::test]
async fn a_server_that_answers_the_first_leg_with_success_is_asked_nothing_further() {
    let (result, seen) = handshake(
        Negotiate::default(),
        Setup::ImmediateSuccess { guest: false },
        options(),
    )
    .await;
    assert!(result.is_ok(), "{:?}", result.err());
    assert_eq!(
        seen.iter()
            .filter(|frame| frame[4] == SESSION_SETUP_ANDX)
            .count(),
        1,
        "a server that issued no challenge is sent no AUTHENTICATE message"
    );

    // Where it does challenge, the client answers, and exactly once.
    let (result, seen) = handshake(
        Negotiate::default(),
        Setup::Challenge { guest: false },
        options(),
    )
    .await;
    assert!(result.is_ok(), "{:?}", result.err());
    assert_eq!(
        seen.iter()
            .filter(|frame| frame[4] == SESSION_SETUP_ANDX)
            .count(),
        2
    );
}

/// A server that admits to requiring signing is named rather than left to
/// surface as access-denied.
///
/// It is documented as necessary but not sufficient: Windows 11 24H2 with
/// `RequireSecuritySignature` set reports neither signature bit, so this check
/// cannot be the detection mechanism in general. What it removes is the class
/// of failure that sends an operator looking at credentials.
#[tokio::test]
async fn a_server_that_requires_signing_says_so() {
    let negotiate = Negotiate {
        security_mode: 0x03 | 0x08,
        ..Negotiate::default()
    };
    let (result, _) = handshake(negotiate, Setup::Challenge { guest: false }, options()).await;
    assert!(matches!(result, Err(Error::SigningRequired)), "{result:?}");
}

/// A response that clears `SMB_FLAGS2_NT_STATUS` is reported as such rather
/// than as a fabricated `NTSTATUS`.
///
/// **What a wrong implementation does**: reads those four header bytes as a
/// 32-bit status when they are an error class, a reserved byte and a 16-bit
/// code, and reports a status number that means nothing.
#[tokio::test]
async fn a_server_answering_outside_nt_status_is_refused() {
    let negotiate = Negotiate {
        nt_status: false,
        ..Negotiate::default()
    };
    let (result, _) = handshake(negotiate, Setup::Challenge { guest: false }, options()).await;
    match result {
        Err(Error::UnsupportedServer(message)) => {
            assert!(message.contains("outside NT status"), "{message}");
        }
        other => panic!("a DOS-format answer must be refused, got {other:?}"),
    }
}

/// A server accepting no dialect on offer is the one diagnosable negotiate
/// failure, and any other index is refused the same way.
#[tokio::test]
async fn a_dialect_index_that_was_not_offered_is_refused() {
    for index in [0xFFFFu16, 1, 2] {
        let negotiate = Negotiate {
            dialect_index: index,
            ..Negotiate::default()
        };
        let (result, _) = handshake(negotiate, Setup::Challenge { guest: false }, options()).await;
        assert!(
            matches!(result, Err(Error::Protocol(_))),
            "index {index}: {result:?}"
        );
    }
}

/// A refusal from the server itself keeps its status, so a wrong password
/// reaches the caller as the status the server sent.
#[tokio::test]
async fn a_refused_logon_carries_the_server_status() {
    let (result, _) = handshake(
        Negotiate::default(),
        Setup::Failure(NtStatus::new(0xC000_006D)),
        options(),
    )
    .await;
    match result {
        Err(error) => assert_eq!(error.status(), Some(NtStatus::new(0xC000_006D))),
        Ok(_) => panic!("a refused logon must fail"),
    }
}

/// What the handshake hands the actor: values it is constructed with rather
/// than state it must observe.
///
/// The client's own `SESSION_SETUP_ANDX` is checked here too, because three of
/// its fields are chosen rather than echoed and nothing else asserts them.
#[tokio::test]
async fn the_negotiated_parameters_reach_the_actor_as_values() {
    let (result, seen) = handshake(
        Negotiate::default(),
        Setup::Challenge { guest: false },
        options(),
    )
    .await;
    let session = result.expect("the handshake completes");
    let negotiated = session.negotiated();
    assert_eq!(negotiated.max_buffer_size, 16_644);
    assert_eq!(negotiated.max_mpx_count, 50);
    assert_eq!(negotiated.capabilities, SAMBA_CAPABILITIES);
    assert_eq!(negotiated.admission_limit(), 50);
    assert_eq!(session.uid(), 0x1234);
    assert_eq!(
        session.server().strings.first().map(String::as_str),
        Some("Scripted")
    );

    let setup = seen
        .iter()
        .find(|frame| frame[4] == SESSION_SETUP_ANDX)
        .expect("a session setup was sent");
    let words = &setup[33..33 + 24];
    // The advertised `MaxBufferSize` is the client's own receive capability and
    // is the largest the `USHORT` field can carry, not the server's number
    // echoed back.
    assert_eq!(u16::from_le_bytes([words[4], words[5]]), u16::MAX);
    // The multiplex count the client advertises is the limit it then enforces.
    assert_eq!(u16::from_le_bytes([words[6], words[7]]), 50);
    // The `SessionKey` is the negotiate response's, echoed as [MS-CIFS] asks.
    assert_eq!(
        u32::from_le_bytes([words[10], words[11], words[12], words[13]]),
        0x0DFF
    );
    // The capability word is the client's own — `CAP_NT_SMBS | CAP_UNICODE |
    // CAP_LARGE_FILES | CAP_STATUS32 | CAP_EXTENDED_SECURITY` plus the two
    // large-I/O bits the server offered — and emphatically not the server's
    // word echoed back.
    let claimed = u32::from_le_bytes([words[20], words[21], words[22], words[23]]);
    assert_eq!(
        claimed,
        0x0000_0010 | 0x0000_0004 | 0x0000_0008 | 0x0000_0040 | 0x8000_0000 | 0xC000
    );
    assert_ne!(claimed, SAMBA_CAPABILITIES);
    // **Windows refuses the session setup without this bit**, answering
    // `ERRSRV`/`ERRerror` in DOS error format with no NT status at all. It is
    // asserted on its own because it is the one bit whose absence no scripted
    // server here would notice.
    assert_ne!(claimed & 0x8000_0000, 0);

    // And the actor took the stream carrying those same values.
    assert_eq!(session.connection().negotiated(), negotiated);
}

/// A client that claims a large-I/O capability the server did not offer would
/// be asserting one against a peer that cannot honour it.
#[tokio::test]
async fn the_large_io_capabilities_are_claimed_only_where_the_server_offered_them() {
    let negotiate = Negotiate {
        capabilities: SAMBA_CAPABILITIES & !(0x4000 | 0x8000),
        ..Negotiate::default()
    };
    let (result, seen) = handshake(negotiate, Setup::Challenge { guest: false }, options()).await;
    assert!(result.is_ok(), "{:?}", result.err());
    let setup = seen
        .iter()
        .find(|frame| frame[4] == SESSION_SETUP_ANDX)
        .expect("a session setup was sent");
    let words = &setup[33..33 + 24];
    let claimed = u32::from_le_bytes([words[20], words[21], words[22], words[23]]);
    assert_eq!(claimed & (0x4000 | 0x8000), 0);
    // The bits that are not conditional stay put.
    assert_ne!(claimed & 0x8000_0000, 0);
}
