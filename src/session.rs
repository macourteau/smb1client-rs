//! The handshake: negotiate and session setup, and the [`Session`] they
//! produce.
//!
//! **The handshake completes before the connection actor takes ownership of the
//! stream.** Negotiate and session setup run on the freshly dialled socket, and
//! what the actor is handed is an already-negotiated, already-authenticated
//! connection. Three consequences follow, and they are why the order is fixed:
//! the handshake is bounded by the connect timeout rather than by the
//! per-request timeout, because there is no request table yet to time anything
//! out in; it consumes no multiplex id, so the pool and the admission limit
//! describe only requests a caller asked for; and the negotiated parameters
//! reach the actor as values it is constructed with rather than as state it
//! must observe — which is exactly what makes them injectable for the test
//! seam.
//!
//! # The four refusals
//!
//! A server this crate declines to talk to is refused *here*, before any
//! operation is attempted and — for three of the four — before any credential
//! reaches the wire:
//!
//! 1. the **capability floor**, which the port requires rather than inherits;
//! 2. **`NEGOTIATE_USER_SECURITY`**, because proceeding against a
//!    share-level-security server sends a password where a share key is
//!    expected;
//! 3. the **`MaxBufferSize` floor** of [`MIN_MAX_BUFFER_SIZE`], whose location
//!    is load-bearing — the chunk-size rules subtract 1,024 from that field, and
//!    validating it once on arrival is what makes every one of those
//!    subtractions safe by construction;
//! 4. the **guest logon**, which on many servers is exactly what a wrong
//!    password produces.
//!
//! None of the four is reachable against any server this campaign tested, so
//! all four are proven over scripted responses on the transport seam.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tracing::{debug, warn};

use crate::auth::{Credentials, ntlm, spnego};
use crate::connection::{Connection, Negotiated, Timeouts, transport};
use crate::error::{Error, Result};
use crate::status::NtStatus;
use crate::wire::header::{FLAGS2_NT_STATUS, SmbHeader, command};
use crate::wire::negotiate::{NegotiateRequest, NegotiateResponse};
use crate::wire::session::{SessionSetupAndx, SessionSetupResponse};
use crate::wire::{Message, netbios, trace};

/// The smallest `MaxBufferSize` this crate will work to.
///
/// It is the SMB1 minimum, and Windows 11 24H2 advertises exactly it. A server
/// negotiating below it is one this campaign never tested and this crate
/// declines, with an error naming the field rather than a failure further in.
pub const MIN_MAX_BUFFER_SIZE: u32 = 4_356;

/// The `MaxBufferSize` this client advertises: the largest the field can carry.
///
/// The field is a `USHORT` in `SESSION_SETUP_ANDX`, unlike the negotiate
/// response's 32-bit field of the same name, so no proposal can raise this. It
/// tells the server the largest SMB message the client will accept, and a
/// server splits a larger reply to fit it — so this number, not anything the
/// server advertises, is the threshold at which a reply arrives in several
/// messages at all.
pub const ADVERTISED_MAX_BUFFER_SIZE: u16 = u16::MAX;

/// `NEGOTIATE_USER_SECURITY` in the negotiate response's `SecurityMode`.
const SECURITY_USER: u8 = 0x01;
/// `NEGOTIATE_SECURITY_SIGNATURES_REQUIRED`.
const SECURITY_SIGNATURES_REQUIRED: u8 = 0x08;

/// The capabilities this crate requires of a server, and refuses one lacking.
///
/// The floor is a decision rather than an inheritance: the port targets nothing
/// that predates any of them. `CAP_EXTENDED_SECURITY` is the one that would
/// otherwise be assumed silently — a server without it sends an 8-byte
/// challenge and expects a raw NTLM response, and a floor that admitted it
/// would fail it inside the SPNEGO decoder, which is the least diagnosable
/// place in the crate to fail.
const REQUIRED_CAPABILITIES: [(u32, &str); 6] = [
    (0x0000_0010, "CAP_NT_SMBS"),
    (0x0000_0004, "CAP_UNICODE"),
    (0x0000_0008, "CAP_LARGE_FILES"),
    (0x0000_0040, "CAP_STATUS32"),
    (0x0000_0200, "CAP_NT_FIND"),
    (CAP_EXTENDED_SECURITY, "CAP_EXTENDED_SECURITY"),
];

/// `CAP_LARGE_READX`.
const CAP_LARGE_READX: u32 = 0x0000_4000;
/// `CAP_LARGE_WRITEX`.
const CAP_LARGE_WRITEX: u32 = 0x0000_8000;

/// `CAP_EXTENDED_SECURITY`, which the client claims as well as requires.
///
/// **Windows refuses the session setup without it.** Measured against Windows
/// 11 24H2: a `SESSION_SETUP_ANDX` carrying a SPNEGO blob under a capability
/// word without this bit is answered `ERRSRV`/`ERRerror` in DOS error format —
/// `Flags2 = 0x8801`, `WordCount = 0` — and authentication never happens at
/// all. The Samba container and the embedded device accept it either way,
/// which is exactly the shape of every defect this campaign found late. It is
/// the request-side counterpart of `SMB_FLAGS2_EXTENDED_SECURITY` in the
/// header, and the crate implements what it claims, so claiming it is not the
/// class of false advertisement the two dropped NTLM flags are.
const CAP_EXTENDED_SECURITY: u32 = 0x8000_0000;

/// The capability word this crate implements and always claims.
const CLIENT_CAPABILITIES: u32 =
    0x0000_0010 | 0x0000_0004 | 0x0000_0008 | 0x0000_0040 | CAP_EXTENDED_SECURITY;

/// What the client calls itself on the wire.
///
/// These identify the crate, by name and version, rather than a host operating
/// system. They are wire-visible identity strings and there is no reason to
/// misreport them — and equally no reason to report the operator's own machine,
/// which is why the NTLM workstation field is sent empty.
const NATIVE_OS: &str = "smb1client-rs";

/// How the handshake is run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionOptions {
    /// The bound on the dial and the handshake together. The handshake half is
    /// what is enforced here.
    pub connect_timeout: Duration,
    /// The bounds the connection actor then works to.
    pub timeouts: Timeouts,
    /// Whether a guest logon is acceptable.
    ///
    /// It defaults to `false`, so a server that quietly downgrades a wrong
    /// password to guest access fails the handshake instead of handing back a
    /// session with whatever rights guests have.
    pub allow_guest: bool,
    /// Whether the tracer writes frame bytes for this run.
    ///
    /// Off by default: a dump of a listing or a read reply carries filenames
    /// and file contents. Turning it on does **not** reach
    /// `SESSION_SETUP_ANDX`, whose byte section the tracer redacts whatever
    /// this says.
    pub dump_wire_bytes: bool,
}

impl Default for SessionOptions {
    fn default() -> Self {
        Self {
            connect_timeout: Duration::from_secs(10),
            timeouts: Timeouts::default(),
            allow_guest: false,
            dump_wire_bytes: false,
        }
    }
}

/// What the server said about itself during the handshake.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerInfo {
    /// The server's capability word, as advertised.
    pub capabilities: u32,
    /// The `SecurityMode` byte.
    pub security_mode: u8,
    /// The largest single SMB message the server will accept.
    pub max_buffer_size: u32,
    /// Whether the server logged the client on as a guest. It is `false` on
    /// every session this crate hands back unless the caller asked for guest
    /// access.
    pub guest: bool,
    /// `NativeOS`, `NativeLanMan` and `PrimaryDomain`, where they decoded.
    /// Diagnostics; nothing branches on them.
    pub strings: Vec<String>,
}

/// An authenticated session on a connection.
///
/// One connection carries exactly one session, so the two have the same life:
/// a session the server discards takes the connection with it.
#[derive(Debug, Clone)]
pub struct Session {
    connection: Connection,
    uid: u16,
    server: ServerInfo,
}

impl Session {
    /// Runs the handshake on a dialled stream and puts the connection actor on
    /// it.
    ///
    /// The stream is consumed: after this returns, the actor owns it and every
    /// later message goes through [`Session::connection`].
    pub async fn establish<S>(
        mut stream: S,
        credentials: &Credentials,
        options: &SessionOptions,
    ) -> Result<Self>
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let handshake = tokio::time::timeout(
            options.connect_timeout,
            run(&mut stream, credentials, options),
        )
        .await
        .map_err(|_| Error::ConnectTimeout)??;

        let connection = transport::spawn(stream, handshake.negotiated, options.timeouts);
        Ok(Self {
            connection,
            uid: handshake.uid,
            server: handshake.server,
        })
    }

    /// The connection this session runs on.
    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    /// The user id the server assigned, which every later request carries.
    pub fn uid(&self) -> u16 {
        self.uid
    }

    /// What the server said about itself.
    pub fn server(&self) -> &ServerInfo {
        &self.server
    }

    /// What the handshake negotiated.
    pub fn negotiated(&self) -> Negotiated {
        self.connection.negotiated()
    }
}

/// What the handshake produced, before the actor exists.
struct Handshake {
    negotiated: Negotiated,
    uid: u16,
    server: ServerInfo,
}

/// The handshake itself, run on a stream nothing else is reading.
async fn run<S>(
    stream: &mut S,
    credentials: &Credentials,
    options: &SessionOptions,
) -> Result<Handshake>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let negotiate = negotiate(stream, options).await?;

    let negotiated = Negotiated {
        max_mpx_count: negotiate.words.max_mpx_count,
        max_buffer_size: negotiate.words.max_buffer_size,
        capabilities: negotiate.words.capabilities,
    };

    let (uid, setup) = session_setup(stream, &negotiate, &negotiated, credentials, options).await?;

    let guest = setup.is_guest();
    if guest && !options.allow_guest {
        warn!("the server logged the client on as a guest; refusing the session");
        return Err(Error::GuestLogon);
    }
    if guest {
        warn!("the server logged the client on as a guest, which the caller allowed");
    }
    debug!(
        uid,
        server = ?setup.server_strings,
        "session established"
    );

    Ok(Handshake {
        negotiated,
        uid,
        server: ServerInfo {
            capabilities: negotiate.words.capabilities,
            security_mode: negotiate.words.security_mode,
            max_buffer_size: negotiate.words.max_buffer_size,
            guest,
            strings: setup.server_strings,
        },
    })
}

/// Offers one dialect, and refuses a server that fails any of the three
/// negotiate-time requirements.
async fn negotiate<S>(stream: &mut S, options: &SessionOptions) -> Result<NegotiateResponse>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let body = NegotiateRequest::single_dialect().encode_body()?;
    let message = send(stream, command::NEGOTIATE, 0, &body, options).await?;
    expect_nt_status(&message)?;
    if message.header().status != NtStatus::SUCCESS {
        return Err(Error::Status(message.header().status));
    }

    let response = NegotiateResponse::decode(&message)?;
    response.accepted_offered_dialect()?;
    let words = &response.words;

    for (bit, name) in REQUIRED_CAPABILITIES {
        if words.capabilities & bit == 0 {
            return Err(Error::UnsupportedServer(format!(
                "the server does not offer {name}, which this crate requires \
                 (Capabilities = {:#010x})",
                words.capabilities
            )));
        }
    }

    if words.security_mode & SECURITY_USER == 0 {
        return Err(Error::UnsupportedServer(format!(
            "the server offers share-level security rather than user-level \
             (SecurityMode = {:#04x}); a password sent to it goes where a share key is expected",
            words.security_mode
        )));
    }

    // Necessary but not sufficient, and documented as such: Windows 11 24H2
    // with `RequireSecuritySignature` set to true reports neither signature
    // bit. What the check removes is a class of failure that would otherwise
    // surface as access-denied and send an operator looking at credentials.
    if words.security_mode & SECURITY_SIGNATURES_REQUIRED != 0 {
        return Err(Error::SigningRequired);
    }

    if words.max_buffer_size < MIN_MAX_BUFFER_SIZE {
        return Err(Error::UnsupportedServer(format!(
            "the server negotiated MaxBufferSize = {}, below the SMB1 minimum of {}",
            words.max_buffer_size, MIN_MAX_BUFFER_SIZE
        )));
    }

    debug!(
        max_buffer_size = words.max_buffer_size,
        max_mpx_count = words.max_mpx_count,
        capabilities = format_args!("{:#010x}", words.capabilities),
        security_mode = format_args!("{:#04x}", words.security_mode),
        "negotiated NT LM 0.12"
    );
    Ok(response)
}

/// The SPNEGO exchange, which is one leg or two.
async fn session_setup<S>(
    stream: &mut S,
    negotiate: &NegotiateResponse,
    negotiated: &Negotiated,
    credentials: &Credentials,
    options: &SessionOptions,
) -> Result<(u16, SessionSetupResponse)>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    // The client claims the capabilities it implements, and the two large-I/O
    // ones only where the server offered them: claiming those against a peer
    // that cannot honour them would assert a capability the connection then
    // cannot use.
    let capabilities =
        CLIENT_CAPABILITIES | (negotiate.words.capabilities & (CAP_LARGE_READX | CAP_LARGE_WRITEX));

    let negotiate_message = ntlm::negotiate_message();
    let mut request = SessionSetupAndx {
        max_buffer_size: ADVERTISED_MAX_BUFFER_SIZE,
        max_mpx_count: u16::try_from(negotiated.admission_limit()).unwrap_or(u16::MAX),
        session_key: negotiate.words.session_key,
        capabilities,
        security_blob: spnego::neg_token_init(&negotiate_message),
        native_os: NATIVE_OS.to_owned(),
        native_lan_man: format!("{NATIVE_OS}/{}", env!("CARGO_PKG_VERSION")),
    };

    let first = send(
        stream,
        command::SESSION_SETUP_ANDX,
        0,
        &request.encode_body()?,
        options,
    )
    .await?;
    expect_nt_status(&first)?;
    let uid = first.header().uid;
    let status = first.header().status;

    // **The exchange can end after the first leg.** A server answering
    // `STATUS_SUCCESS` here has issued no challenge and wants no AUTHENTICATE
    // message. That is not a curiosity to tolerate: it is precisely the shape a
    // guest downgrade takes, a server declining to challenge credentials it has
    // decided not to check. So this response is handed back and the guest check
    // runs on it exactly as it does on the longer path.
    if status == NtStatus::SUCCESS {
        debug!("the server completed the session setup without a challenge");
        return Ok((uid, SessionSetupResponse::decode(&first)?));
    }
    if status != NtStatus::MORE_PROCESSING_REQUIRED {
        return Err(Error::Status(status));
    }

    let challenge_response = SessionSetupResponse::decode(&first)?;
    let challenge_token = spnego::response_token(&challenge_response.security_blob)
        .map_err(|error| Error::Protocol(Box::new(error)))?;
    let challenge = ntlm::Challenge::parse(&challenge_token)
        .map_err(|error| Error::Protocol(Box::new(error)))?;

    let client_values = ntlm::ClientValues::fresh().map_err(|error| {
        Error::Io(std::io::Error::other(format!(
            "the operating system's entropy source failed: {error}"
        )))
    })?;
    let authenticate =
        ntlm::authenticate(&negotiate_message, &challenge, credentials, &client_values);
    let mic = authenticate.mech_list_mic(&spnego::mech_list());
    request.security_blob = spnego::neg_token_resp(&authenticate.message, &mic);

    let second = send(
        stream,
        command::SESSION_SETUP_ANDX,
        uid,
        &request.encode_body()?,
        options,
    )
    .await?;
    expect_nt_status(&second)?;
    if second.header().status != NtStatus::SUCCESS {
        return Err(Error::Status(second.header().status));
    }
    Ok((second.header().uid, SessionSetupResponse::decode(&second)?))
}

/// Refuses a response that answered outside NT status altogether.
///
/// `SMB_FLAGS2_NT_STATUS` is a *per-message* flag and a server may clear it
/// however the request was flagged. Reading the flag costs one branch, and not
/// reading it means reporting a status number that means nothing: those four
/// header bytes would be an error class, a reserved byte and a 16-bit code
/// instead. The DOS class is not mapped onto NT statuses — the capability floor
/// requires `CAP_STATUS32`, so a server doing this is outside what this crate
/// targets, and the honest report is that it happened.
fn expect_nt_status(message: &Message) -> Result<()> {
    if message.header().flags2 & FLAGS2_NT_STATUS == 0 {
        return Err(Error::UnsupportedServer(format!(
            "the server answered command {:#04x} outside NT status \
             (Flags2 = {:#06x}), which the CAP_STATUS32 floor forbids",
            message.header().command,
            message.header().flags2
        )));
    }
    Ok(())
}

/// Sends one request and reads the reply.
///
/// The handshake is strictly serial and runs before the actor exists, so this
/// is a plain write-then-read rather than anything the request table has to
/// know about. It consumes no multiplex id: every handshake message carries
/// zero.
async fn send<S>(
    stream: &mut S,
    command: u8,
    uid: u16,
    body: &[u8],
    options: &SessionOptions,
) -> Result<Message>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = SmbHeader::request(command);
    header.uid = uid;
    let message = crate::wire::message(&header, body)?;
    trace::frame(
        trace::Direction::Outbound,
        &message,
        options.dump_wire_bytes,
    );
    stream.write_all(&crate::wire::frame(&message)?).await?;
    stream.flush().await?;

    loop {
        let mut netbios_header = [0u8; netbios::HEADER_LEN];
        stream.read_exact(&mut netbios_header).await?;
        let (kind, length) = netbios::decode_header(netbios_header)?;
        let mut body = vec![0u8; length];
        stream.read_exact(&mut body).await?;
        // A keep-alive is transport-level and carries nothing. The handshake
        // meets one only from a server that sends them unprompted, and reading
        // past it is the whole of what it needs.
        if kind == netbios::MessageType::KeepAlive {
            continue;
        }
        trace::frame(trace::Direction::Inbound, &body, options.dump_wire_bytes);
        let message = Message::parse(body)?;
        if message.header().command != command {
            return Err(Error::UnsupportedServer(format!(
                "the server answered command {:#04x} with command {:#04x}",
                command,
                message.header().command
            )));
        }
        return Ok(message);
    }
}
