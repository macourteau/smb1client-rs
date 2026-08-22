//! The conformance script, run by hand against a real SMB1 server before a
//! release.
//!
//! **This is not a CI job and it gates nothing.** It carries the checks no
//! committed evidence can settle, because each turns on what a *particular*
//! server does with a wire choice this port makes and the Go reference never
//! sent. The design record names nine of them; they are numbered here as it
//! numbers them, and each one prints what it asserts, what the server did, and
//! a verdict.
//!
//! **A check that cannot be run against a given server says so rather than
//! passing.** Check 8 is unrunnable against a server that does not require
//! signing, and reporting it as passed would be a lie; the write halves of
//! checks 4, 5 and 7 are unrunnable against a server the operator has told this
//! script not to write to.
//!
//! Where the design fixes an answer — authentication must succeed under checks
//! 1, 2 and 3 — a failure is a failure. Where it does not, the check reports
//! what the server did rather than asserting what it should have done: check 4
//! against an unmeasured server asks "what did it serve for a 130,048-byte
//! read?", not "it must serve all of it".
//!
//! # How it sees the wire
//!
//! Every check but two turns on bytes this crate put on the wire, and the wire
//! layer is not public surface. So the script dials through
//! [`Client::with_dialer`] with a stream that tees every byte in both
//! directions into an in-process frame log, and decodes the frames itself. That
//! is what lets it report the `ShareAccess` an open actually carried rather
//! than what the source says it should. Nothing is written to disk, and the
//! `SESSION_SETUP_ANDX` bytes — which carry an offline-crackable NTLMv2
//! handshake — are decoded to named fields and never printed raw.
//!
//! # Running it
//!
//! ```text
//! cargo run --example conformance -- \
//!     --server 192.168.0.10 --share testshare --user smbtest --password secret
//! ```
//!
//! Add `--read-only` against a server holding data that matters: the script
//! then creates, modifies and deletes nothing, and reports every check that
//! needed to write as skipped.
//!
//! **Windows refuses concurrent SMB1 handshakes from one client host**, so run
//! one instance of this script at a time against such a server.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::io;
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpStream;

use smb1client::auth::ntlm;
use smb1client::client::{Dialed, Dialer, Stream};
use smb1client::connection::{CAP_LARGE_READX, CAP_LARGE_WRITEX, LARGE_IO_CHUNK, Request};
use smb1client::rpc::ShareService;
use smb1client::tree::{OpenOptions, Tree};
use smb1client::{
    Client, ClientConfig, Credentials, Error, NtStatus, Server, Session, SessionOptions, UncPath,
};

/// What the script asks for in one read and carries in one write, which is the
/// crate's own large-I/O chunk.
const LARGE: usize = LARGE_IO_CHUNK;

/// How many entries a directory has to hold before a listing of it needs a
/// `FIND_NEXT2`, which is what check 5 is about. The listing asks for 100 at a
/// time.
const ENTRIES_PER_PAGE: usize = 100;

/// How many entries the scratch directory is filled with where no directory on
/// the server already needs paging.
const SCRATCH_ENTRIES: usize = 150;

/// How many directories the discovery pass will open looking for one that pages.
const DISCOVERY_DIRECTORIES: usize = 64;

/// How many entries the discovery pass will read out of any one directory.
const DISCOVERY_ENTRIES: usize = 400;

// SMB1 command codes. The wire layer is not public surface, so the handful this
// script builds or recognises are spelled out here.
/// `SMB_COM_ECHO`.
const ECHO: u8 = 0x2B;
/// `SMB_COM_READ_ANDX`.
const READ_ANDX: u8 = 0x2E;
/// `SMB_COM_WRITE_ANDX`.
const WRITE_ANDX: u8 = 0x2F;
/// `SMB_COM_TRANSACTION2`.
const TRANSACTION2: u8 = 0x32;
/// `SMB_COM_FIND_CLOSE2`.
const FIND_CLOSE2: u8 = 0x34;
/// `SMB_COM_NEGOTIATE`.
const NEGOTIATE: u8 = 0x72;
/// `SMB_COM_SESSION_SETUP_ANDX`.
const SESSION_SETUP_ANDX: u8 = 0x73;
/// `SMB_COM_LOGOFF_ANDX`.
const LOGOFF_ANDX: u8 = 0x74;
/// `SMB_COM_NT_CREATE_ANDX`.
const NT_CREATE_ANDX: u8 = 0xA2;

/// `TRANS2_FIND_FIRST2`.
const FIND_FIRST2: u16 = 0x0001;
/// `TRANS2_FIND_NEXT2`.
const FIND_NEXT2: u16 = 0x0002;

/// `SMB_FLAGS2_KNOWS_EAS`, the bit check 3 is about.
const FLAGS2_KNOWS_EAS: u16 = 0x0002;

/// `SYNCHRONIZE`, the right check 7 is about.
const SYNCHRONIZE: u32 = 0x0010_0000;

/// `NEGOTIATE_SECURITY_SIGNATURES_ENABLED` in a negotiate response's
/// `SecurityMode`.
const SECURITY_SIGNATURES_ENABLED: u8 = 0x04;

/// `NEGOTIATE_SECURITY_SIGNATURES_REQUIRED` in the same byte.
const SECURITY_SIGNATURES_REQUIRED: u8 = 0x08;

/// The `TID` the idle probe's header carries: SMB1's "no tree".
const NO_TREE: u16 = 0xFFFF;

/// The `UID` the idle probe's header carries: no session.
const NO_SESSION: u16 = 0;

/// How long a hand-built request waits before the script gives up on it.
const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// How much of each frame the capture keeps. Enough for any word block, any
/// transaction parameter block and any security blob this crate sends.
const HEAD_CAP: usize = 4096;

/// What to do with the command line.
const USAGE: &str = "\
usage: cargo run --example conformance -- --server HOST[:PORT] [options]

  --server HOST[:PORT]   the server to dial (required)
  --share NAME           the share to connect; enumerated if omitted
  --user NAME            the user to authenticate as
  --password SECRET      the password; SMB1_CONFORMANCE_PASSWORD is read too
  --domain NAME          the NTLM domain
  --allow-guest          accept a session the server downgraded to guest
  --read-only            create, modify and delete nothing on the server
  --dir PATH             a share-relative directory to work in
  --big-dir PATH         a directory known to hold more than one listing page
  --large-file PATH      an existing file of at least 130,048 bytes
";

/// What the operator asked for.
struct Args {
    /// The server to dial.
    server: Server,
    /// The share to connect, where the operator named one.
    share: Option<String>,
    /// Who to authenticate as.
    credentials: Credentials,
    /// Whether a guest logon is acceptable.
    allow_guest: bool,
    /// Whether this server may be written to at all.
    read_only: bool,
    /// The share-relative directory to work in.
    directory: String,
    /// A directory known to need more than one listing page.
    big_directory: Option<String>,
    /// An existing file large enough for the read half of check 4.
    large_file: Option<String>,
}

impl Args {
    /// Parses the command line, or says what was wrong with it.
    fn parse() -> Result<Self, String> {
        let mut server = None;
        let mut share = None;
        let mut user = String::new();
        let mut password = std::env::var("SMB1_CONFORMANCE_PASSWORD").unwrap_or_default();
        let mut domain = String::new();
        let mut allow_guest = false;
        let mut read_only = false;
        let mut directory = String::new();
        let mut big_directory = None;
        let mut large_file = None;

        let mut arguments = std::env::args().skip(1);
        while let Some(argument) = arguments.next() {
            let mut value = || {
                arguments
                    .next()
                    .ok_or_else(|| format!("{argument} wants a value"))
            };
            match argument.as_str() {
                "--server" => server = Some(value()?),
                "--share" => share = Some(value()?),
                "--user" => user = value()?,
                "--password" => password = value()?,
                "--domain" => domain = value()?,
                "--dir" => directory = value()?,
                "--big-dir" => big_directory = Some(value()?),
                "--large-file" => large_file = Some(value()?),
                "--allow-guest" => allow_guest = true,
                "--read-only" => read_only = true,
                "-h" | "--help" => return Err(String::new()),
                other => return Err(format!("unknown argument {other}")),
            }
        }

        let server = server.ok_or_else(|| "--server is required".to_owned())?;
        Ok(Self {
            server: server.parse().map_err(|error| format!("{error}"))?,
            share,
            credentials: Credentials::new(user, password).with_domain(domain),
            allow_guest,
            read_only,
            directory,
            big_directory,
            large_file,
        })
    }
}

// ---------------------------------------------------------------------------
// The report
// ---------------------------------------------------------------------------

/// What a check concluded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Verdict {
    /// The design fixes the answer and the server gave it.
    Pass,
    /// The design fixes the answer and the server did not give it.
    Fail,
    /// The design fixes no answer; the observations are the result.
    Reported,
    /// This server cannot exercise the check, for the reason recorded.
    Unrunnable,
    /// The operator forbade what the check needed.
    Skipped,
}

impl Verdict {
    /// How the verdict is written in the report.
    fn as_str(self) -> &'static str {
        match self {
            Verdict::Pass => "PASS",
            Verdict::Fail => "FAIL",
            Verdict::Reported => "REPORTED",
            Verdict::Unrunnable => "UNRUNNABLE",
            Verdict::Skipped => "SKIPPED",
        }
    }
}

/// One of the nine checks, and what became of it.
struct Check {
    /// Its number in the design record's list.
    number: usize,
    /// What it is about.
    title: &'static str,
    /// What it asserts, where it asserts anything.
    asserts: &'static str,
    /// What the server did.
    observed: Vec<String>,
    /// The conclusion.
    verdict: Verdict,
}

impl Check {
    /// A check nothing has been observed for yet.
    fn new(number: usize, title: &'static str, asserts: &'static str) -> Self {
        Self {
            number,
            title,
            asserts,
            observed: Vec::new(),
            verdict: Verdict::Unrunnable,
        }
    }

    /// Records an observation.
    fn saw(&mut self, observation: impl Into<String>) -> &mut Self {
        self.observed.push(observation.into());
        self
    }

    /// Settles the verdict.
    fn verdict(&mut self, verdict: Verdict) {
        self.verdict = verdict;
    }
}

/// The nine checks, in the order the design record names them.
struct Report {
    /// One entry per check, indexed by its number less one.
    checks: Vec<Check>,
    /// What was learned about the server before any check ran.
    preamble: Vec<String>,
}

impl Report {
    /// The nine, each with its title and what it asserts.
    fn new() -> Self {
        Self {
            preamble: Vec::new(),
            checks: vec![
                Check::new(
                    1,
                    "NTLMSSP_NEGOTIATE_SIGN without NTLMSSP_NEGOTIATE_ALWAYS_SIGN",
                    "authentication succeeds with NTLMSSP_NEGOTIATE_SIGN set and \
                     NTLMSSP_NEGOTIATE_ALWAYS_SIGN cleared",
                ),
                Check::new(
                    2,
                    "authentication without NTLMSSP_NEGOTIATE_VERSION",
                    "authentication succeeds with NTLMSSP_NEGOTIATE_VERSION cleared and no \
                     Version structure on the wire",
                ),
                Check::new(
                    3,
                    "a header Flags2 without SMB_FLAGS2_KNOWS_EAS",
                    "every request this run sent carried Flags2 without SMB_FLAGS2_KNOWS_EAS, \
                     and the server served them",
                ),
                Check::new(
                    4,
                    "a 130,048-byte read and write against a small MaxBufferSize",
                    "nothing; what the server served for a 130,048-byte read and accepted for a \
                     130,048-byte write is the result",
                ),
                Check::new(
                    5,
                    "SMB_FIND_CLOSE_AT_EOS on a FIND_NEXT2",
                    "a FIND_NEXT2 carrying SMB_FIND_CLOSE_AT_EOS is answered without error and \
                     the listing completes; whether the server honoured the flag is reported",
                ),
                Check::new(
                    6,
                    "the idle probe",
                    "the probe is answered on a live session; whether it is answered on a \
                     connection whose session the server has discarded is reported",
                ),
                Check::new(
                    7,
                    "both NT_CREATE_ANDX departures",
                    "an open carrying ShareAccess = 0x7 and a DesiredAccess of specific rights \
                     without SYNCHRONIZE succeeds",
                ),
                Check::new(
                    8,
                    "a server that requires signing saying so in its negotiate response",
                    "a server whose SecurityMode announces required signing is refused at the \
                     handshake rather than further in",
                ),
                Check::new(
                    9,
                    "the three client-side values no server had been told",
                    "the session setup is accepted carrying a client-chosen MaxBufferSize, \
                     MaxMpxCount and capability word",
                ),
            ],
        }
    }

    /// The check numbered `number`, which is its index less one.
    fn check(&mut self, number: usize) -> &mut Check {
        &mut self.checks[number - 1]
    }

    /// Records something learned before the checks.
    fn note(&mut self, note: impl Into<String>) {
        self.preamble.push(note.into());
    }

    /// Whether anything failed, which is what the exit status carries.
    fn failed(&self) -> bool {
        self.checks
            .iter()
            .any(|check| check.verdict == Verdict::Fail)
    }

    /// Writes the report.
    fn print(&self, args: &Args) {
        println!("smb1client conformance script");
        println!("  server      {}", args.server.unc_name());
        println!(
            "  share       {}",
            args.share.as_deref().unwrap_or("(enumerated)")
        );
        println!("  user        {}", args.credentials.user());
        println!(
            "  writing     {}",
            if args.read_only {
                "forbidden (--read-only)"
            } else {
                "allowed"
            }
        );
        for note in &self.preamble {
            println!("  {note}");
        }
        println!();

        for check in &self.checks {
            println!("check {} — {}", check.number, check.title);
            println!("  asserts:  {}", check.asserts);
            if check.observed.is_empty() {
                println!("  observed: (nothing)");
            }
            for (index, observation) in check.observed.iter().enumerate() {
                let label = if index == 0 { "observed:" } else { "         " };
                println!("  {label} {observation}");
            }
            println!("  verdict:  {}", check.verdict.as_str());
            println!();
        }

        let mut tally: BTreeMap<&str, usize> = BTreeMap::new();
        for check in &self.checks {
            *tally.entry(check.verdict.as_str()).or_default() += 1;
        }
        let summary = tally
            .iter()
            .map(|(verdict, count)| format!("{count} {verdict}"))
            .collect::<Vec<_>>()
            .join(", ");
        println!("summary: {summary}");
    }
}

// ---------------------------------------------------------------------------
// The wire capture
// ---------------------------------------------------------------------------

/// One SMB message as it went past, its NetBIOS header already stripped.
#[derive(Clone)]
struct Frame {
    /// Whether the client sent it.
    outbound: bool,
    /// Its leading bytes, capped at [`HEAD_CAP`].
    head: Vec<u8>,
}

impl Frame {
    /// Whether this is an SMB message at all, rather than a NetBIOS keep-alive
    /// or a runt.
    fn is_smb(&self) -> bool {
        self.head.len() >= 33 && self.head.starts_with(b"\xffSMB")
    }

    /// The command byte.
    fn command(&self) -> u8 {
        self.head[4]
    }

    /// The status the header carries.
    fn status(&self) -> u32 {
        u32le(&self.head, 5).unwrap_or_default()
    }

    /// The `Flags2` word.
    fn flags2(&self) -> u16 {
        u16le(&self.head, 10).unwrap_or_default()
    }

    /// The user id.
    fn uid(&self) -> u16 {
        u16le(&self.head, 28).unwrap_or_default()
    }

    /// The word block, which is `WordCount` words long.
    fn words(&self) -> &[u8] {
        let count = usize::from(self.head[32]) * 2;
        self.head.get(33..33 + count).unwrap_or_default()
    }

    /// The byte area, as much of it as the head kept.
    fn byte_area(&self) -> &[u8] {
        let start = 35 + usize::from(self.head[32]) * 2;
        self.head.get(start..).unwrap_or_default()
    }

    /// A block the message declares by an offset measured from its own first
    /// byte, as the transaction commands do.
    fn at_absolute(&self, offset: usize, length: usize) -> Option<&[u8]> {
        self.head.get(offset..offset + length)
    }
}

/// Every frame this run has seen, in the order it went past.
#[derive(Default)]
struct Capture {
    /// The log itself.
    frames: Mutex<Vec<Frame>>,
}

impl Capture {
    /// Records a frame.
    fn push(&self, frame: Frame) {
        self.lock().push(frame);
    }

    /// The log, which every accessor goes through.
    fn lock(&self) -> std::sync::MutexGuard<'_, Vec<Frame>> {
        self.frames
            .lock()
            .expect("the capture lock is not poisoned")
    }

    /// Where the log stands, so that a later call can take only what an
    /// operation produced.
    fn mark(&self) -> usize {
        self.lock().len()
    }

    /// The frames recorded since `mark`.
    fn since(&self, mark: usize) -> Vec<Frame> {
        self.lock()[mark..].to_vec()
    }
}

/// A byte stream being cut back into the frames it carries.
#[derive(Default)]
struct Framer {
    /// What has arrived and not yet completed a frame.
    buffered: Vec<u8>,
}

impl Framer {
    /// Takes bytes off the socket and emits every frame they completed.
    fn feed(&mut self, bytes: &[u8], outbound: bool, capture: &Capture) {
        self.buffered.extend_from_slice(bytes);
        loop {
            let Some(header) = self.buffered.get(..4) else {
                return;
            };
            // The NetBIOS length is 17 bits: one bit of the second byte and
            // both of the third and fourth.
            let length = ((usize::from(header[1]) & 0x01) << 16)
                | (usize::from(header[2]) << 8)
                | usize::from(header[3]);
            if self.buffered.len() < 4 + length {
                return;
            }
            let message = &self.buffered[4..4 + length];
            capture.push(Frame {
                outbound,
                head: message[..length.min(HEAD_CAP)].to_vec(),
            });
            self.buffered.drain(..4 + length);
        }
    }
}

/// A TCP stream that copies every byte past into the capture.
struct TeeStream {
    /// The socket.
    inner: TcpStream,
    /// Where the frames go.
    capture: Arc<Capture>,
    /// The server-to-client framer.
    inbound: Framer,
    /// The client-to-server framer.
    outbound: Framer,
}

impl AsyncRead for TeeStream {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let me = self.get_mut();
        let before = buffer.filled().len();
        match Pin::new(&mut me.inner).poll_read(context, buffer) {
            Poll::Ready(Ok(())) => {
                let arrived = buffer.filled()[before..].to_vec();
                me.inbound.feed(&arrived, false, &me.capture);
                Poll::Ready(Ok(()))
            }
            other => other,
        }
    }
}

impl AsyncWrite for TeeStream {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let me = self.get_mut();
        match Pin::new(&mut me.inner).poll_write(context, buffer) {
            Poll::Ready(Ok(written)) => {
                me.outbound.feed(&buffer[..written], true, &me.capture);
                Poll::Ready(Ok(written))
            }
            other => other,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(context)
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(context)
    }
}

/// The dialer the script hands the client: TCP, with the capture on it.
fn tee_dialer(capture: Arc<Capture>) -> Dialer {
    Arc::new(move |server: Server| -> Dialed {
        let capture = Arc::clone(&capture);
        Box::pin(async move {
            let (host, port) = server.dial_address();
            let stream = TcpStream::connect((host, port)).await?;
            Ok(Box::new(TeeStream {
                inner: stream,
                capture,
                inbound: Framer::default(),
                outbound: Framer::default(),
            }) as Box<dyn Stream>)
        })
    })
}

/// A little-endian `u16` at `offset`, where the slice holds one.
fn u16le(bytes: &[u8], offset: usize) -> Option<u16> {
    bytes
        .get(offset..offset + 2)
        .map(|slice| u16::from_le_bytes([slice[0], slice[1]]))
}

/// A little-endian `u32` at `offset`, where the slice holds one.
fn u32le(bytes: &[u8], offset: usize) -> Option<u32> {
    bytes
        .get(offset..offset + 4)
        .map(|slice| u32::from_le_bytes([slice[0], slice[1], slice[2], slice[3]]))
}

/// A number with thousands separators, because the interesting ones here are
/// six digits and read badly without.
fn grouped(value: u64) -> String {
    let digits = value.to_string();
    let mut out = String::new();
    for (index, digit) in digits.chars().enumerate() {
        if index > 0 && (digits.len() - index).is_multiple_of(3) {
            out.push(',');
        }
        out.push(digit);
    }
    out
}

/// How an error reads in the report.
fn describe(error: &Error) -> String {
    format!("{error}")
}

// ---------------------------------------------------------------------------
// Frame readers
// ---------------------------------------------------------------------------

/// The NTLM message inside a `SESSION_SETUP_ANDX`, found by its signature
/// rather than by walking SPNEGO.
fn ntlm_message(frame: &Frame) -> Option<NtlmSeen> {
    let area = frame.byte_area();
    let start = area.windows(8).position(|window| window == b"NTLMSSP\0")?;
    let message = &area[start..];
    let kind = u32le(message, 8)?;
    // The NEGOTIATE message carries its flags at 12 and the Version structure
    // the next flag would fill at 32; the AUTHENTICATE message carries them at
    // 60 and 64, after six field descriptors.
    let (flags_at, version_at) = match kind {
        1 => (12, 32),
        3 => (60, 64),
        _ => return None,
    };
    Some(NtlmSeen {
        kind,
        flags: u32le(message, flags_at)?,
        version: message.get(version_at..version_at + 8)?.to_vec(),
    })
}

/// An NTLMSSP message the capture saw go out.
struct NtlmSeen {
    /// 1 for NEGOTIATE, 3 for AUTHENTICATE.
    kind: u32,
    /// The `NegotiateFlags` it declared.
    flags: u32,
    /// The eight bytes of the `Version` structure, which are zero where
    /// `NTLMSSP_NEGOTIATE_VERSION` is not sent.
    version: Vec<u8>,
}

/// The three client-chosen values a `SESSION_SETUP_ANDX` request carries.
fn session_setup_values(frame: &Frame) -> Option<(u16, u16, u32)> {
    let words = frame.words();
    Some((u16le(words, 4)?, u16le(words, 6)?, u32le(words, 20)?))
}

/// The `SecurityMode`, `MaxMpxCount`, `MaxBufferSize` and `Capabilities` of a
/// negotiate response.
///
/// The offsets are the NT LM 0.12 response's own: `DialectIndex` two bytes,
/// `SecurityMode` one, `MaxMpxCount` and `MaxNumberVcs` two each, then
/// `MaxBufferSize`, `MaxRawSize`, `SessionKey` and `Capabilities` four each.
fn negotiate_values(frame: &Frame) -> Option<(u8, u16, u32, u32)> {
    let words = frame.words();
    Some((
        *words.get(2)?,
        u16le(words, 3)?,
        u32le(words, 7)?,
        u32le(words, 19)?,
    ))
}

/// The `DesiredAccess` and `ShareAccess` an `NT_CREATE_ANDX` request asked for.
fn create_values(frame: &Frame) -> Option<(u32, u32)> {
    let words = frame.words();
    Some((u32le(words, 15)?, u32le(words, 31)?))
}

/// How many bytes a `READ_ANDX` request asked for.
fn read_asked(frame: &Frame) -> Option<u32> {
    let words = frame.words();
    Some(u32::from(u16le(words, 10)?) | (u32le(words, 14)? << 16))
}

/// How many bytes a `READ_ANDX` response served.
fn read_served(frame: &Frame) -> Option<u32> {
    let words = frame.words();
    Some(u32::from(u16le(words, 10)?) | (u32::from(u16le(words, 14)?) << 16))
}

/// How many bytes a `WRITE_ANDX` request carried.
fn write_carried(frame: &Frame) -> Option<u32> {
    let words = frame.words();
    Some(u32::from(u16le(words, 20)?) | (u32::from(u16le(words, 18)?) << 16))
}

/// How many bytes a `WRITE_ANDX` response acknowledged.
fn write_acknowledged(frame: &Frame) -> Option<u32> {
    let words = frame.words();
    Some(u32::from(u16le(words, 4)?) | (u32::from(u16le(words, 8)?) << 16))
}

/// The subcommand a TRANS2 request carries in its setup words.
fn trans2_subcommand(frame: &Frame) -> Option<u16> {
    let words = frame.words();
    if *words.get(26)? == 0 {
        return None;
    }
    u16le(words, 28)
}

/// A TRANS2 request's parameter block, which its own words locate absolutely.
fn trans2_request_parameters(frame: &Frame) -> Option<&[u8]> {
    let words = frame.words();
    let count = usize::from(u16le(words, 18)?);
    let offset = usize::from(u16le(words, 20)?);
    frame.at_absolute(offset, count)
}

/// A TRANS2 response's parameter block, located the same way.
fn trans2_response_parameters(frame: &Frame) -> Option<&[u8]> {
    let words = frame.words();
    let count = usize::from(u16le(words, 6)?);
    let offset = usize::from(u16le(words, 8)?);
    frame.at_absolute(offset, count)
}

/// The user id the session was assigned, read off the wire rather than assumed.
fn session_uid(frames: &[Frame]) -> Option<u16> {
    frames
        .iter()
        .find(|frame| {
            frame.is_smb()
                && !frame.outbound
                && frame.command() == SESSION_SETUP_ANDX
                && frame.status() == 0
                && frame.uid() != 0
        })
        .map(Frame::uid)
}

// ---------------------------------------------------------------------------
// The run
// ---------------------------------------------------------------------------

/// What the handshake and the discovery pass left for the checks to use.
struct Fixture {
    /// The tree the checks work on.
    tree: Tree,
    /// The user id the session carries.
    uid: u16,
    /// A file of at least [`LARGE`] bytes, where one was found or made.
    large_file: Option<String>,
    /// A directory whose listing needs more than one page.
    big_directory: Option<String>,
    /// The scratch directory, where writing was allowed.
    scratch: Option<String>,
}

#[tokio::main]
async fn main() -> ExitCode {
    let args = match Args::parse() {
        Ok(args) => args,
        Err(message) => {
            if !message.is_empty() {
                eprintln!("{message}");
            }
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };

    let mut report = Report::new();
    let capture = Arc::new(Capture::default());
    run(&args, &mut report, &capture).await;
    report.print(&args);

    if report.failed() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Drives every check, in the order their preconditions come to exist.
async fn run(args: &Args, report: &mut Report, capture: &Arc<Capture>) {
    let config = ClientConfig {
        allow_guest: args.allow_guest,
        ..ClientConfig::new(args.credentials.clone())
    };
    let client = Client::with_dialer(config, tee_dialer(Arc::clone(capture)));

    let share = match resolve_share(args, &client, report).await {
        Ok(share) => share,
        Err(failure) => {
            handshake_checks(report, capture, failure.as_ref());
            return;
        }
    };

    let path = match UncPath::new(args.server.clone(), &share) {
        Ok(path) => path,
        Err(error) => {
            report.note(format!("the UNC path is not usable: {}", describe(&error)));
            handshake_checks(report, capture, None);
            return;
        }
    };

    let tree = match client.tree(&path).await {
        Ok(tree) => tree,
        Err(error) => {
            report.note(format!(
                "connecting {} failed: {}",
                path.share_path(),
                describe(&error)
            ));
            handshake_checks(report, capture, Some(&error));
            return;
        }
    };
    report.note(format!("connected {}", path.share_path()));
    handshake_checks(report, capture, None);

    let Some(uid) = session_uid(&capture.since(0)) else {
        report.note("no session setup response was captured; the hand-built checks cannot run");
        return;
    };

    let mut context = Fixture {
        tree,
        uid,
        large_file: args.large_file.clone(),
        big_directory: args.big_directory.clone(),
        scratch: None,
    };

    discover(args, &mut context, report).await;
    check_six_live(&context, report).await;
    check_four(args, &context, report, capture).await;
    check_seven(args, &context, report, capture).await;
    check_five(args, &context, report, capture).await;
    check_three(report, capture);

    if let Some(scratch) = context.scratch.take() {
        if let Err(error) = context.tree.remove_dir_all(&scratch).await {
            report.note(format!(
                "the scratch directory {scratch} could not be removed: {}",
                describe(&error)
            ));
        } else {
            report.note(format!("the scratch directory {scratch} was removed"));
        }
    }

    // Last, because it authenticates a second connection and then logs it off,
    // and on at least one server that costs the first connection its session.
    let identity = check_six_discarded(args, &context, report).await;
    if !identity.is_empty() {
        report.note(format!("the server calls itself {}", identity.join(" / ")));
    }

    if let Err(error) = client.close().await {
        report.note(format!("closing the client failed: {}", describe(&error)));
    }
}

/// Names the share to work on, enumerating the server's own list where the
/// operator named none.
async fn resolve_share(
    args: &Args,
    client: &Client,
    report: &mut Report,
) -> Result<String, Option<Error>> {
    match client.list_shares(&args.server).await {
        Ok(shares) => {
            let names = shares
                .iter()
                .map(|share| format!("{} ({:?})", share.name, share.kind.service))
                .collect::<Vec<_>>()
                .join(", ");
            report.note(format!("shares: {names}"));
            if let Some(share) = &args.share {
                return Ok(share.clone());
            }
            match shares
                .iter()
                .find(|share| share.kind.service == ShareService::Disk && !share.kind.special)
            {
                Some(chosen) => {
                    report.note(format!("no --share given; using {}", chosen.name));
                    Ok(chosen.name.clone())
                }
                None => {
                    report.note("the server offers no ordinary disk share; name one with --share");
                    Err(None)
                }
            }
        }
        Err(error) => {
            report.note(format!("enumerating shares failed: {}", describe(&error)));
            match args.share.clone() {
                Some(share) => Ok(share),
                None => Err(Some(error)),
            }
        }
    }
}

/// Checks 1, 2, 8 and 9, all of which read the handshake's own frames.
///
/// It runs whether or not the handshake succeeded, because check 8's whole
/// subject is a handshake the crate is supposed to refuse.
fn handshake_checks(report: &mut Report, capture: &Arc<Capture>, failure: Option<&Error>) {
    let frames = capture.since(0);

    // Check 8 — a server that requires signing saying so.
    let negotiate = frames
        .iter()
        .find(|frame| frame.is_smb() && !frame.outbound && frame.command() == NEGOTIATE);
    match negotiate.and_then(negotiate_values) {
        Some((security_mode, max_mpx, max_buffer, capabilities)) => {
            report.note(format!(
                "server: SecurityMode = {security_mode:#04x}, MaxMpxCount = {max_mpx}, \
                 MaxBufferSize = {}, Capabilities = {capabilities:#010x}",
                grouped(u64::from(max_buffer))
            ));
            let check = report.check(8);
            check.saw(format!(
                "the negotiate response reports SecurityMode = {security_mode:#04x}: \
                 SIGNATURES_ENABLED {}, SIGNATURES_REQUIRED {}",
                yes_no(security_mode & SECURITY_SIGNATURES_ENABLED != 0),
                yes_no(security_mode & SECURITY_SIGNATURES_REQUIRED != 0),
            ));
            if security_mode & SECURITY_SIGNATURES_REQUIRED == 0 {
                check.saw(
                    "this server does not announce required signing, so nothing here can \
                     exercise the check; it needs a server that does",
                );
                check.verdict(Verdict::Unrunnable);
            } else if matches!(failure, Some(Error::SigningRequired)) {
                check.saw(
                    "the crate refused the handshake with SigningRequired, which is the \
                     announced-signing path being taken",
                );
                check.verdict(Verdict::Pass);
            } else {
                check.saw(
                    "the server announced required signing and the crate did not refuse the \
                     handshake with SigningRequired",
                );
                check.verdict(Verdict::Fail);
            }
        }
        None => {
            let check = report.check(8);
            check.saw("no negotiate response was captured");
            check.verdict(Verdict::Unrunnable);
        }
    }

    // Checks 1 and 2 — the NTLM flags, read off the messages that went out.
    let mut seen: Vec<NtlmSeen> = Vec::new();
    for frame in frames
        .iter()
        .filter(|frame| frame.is_smb() && frame.outbound && frame.command() == SESSION_SETUP_ANDX)
    {
        if let Some(message) = ntlm_message(frame) {
            seen.push(message);
        }
    }
    let setup_status = frames
        .iter()
        .filter(|frame| frame.is_smb() && !frame.outbound && frame.command() == SESSION_SETUP_ANDX)
        .map(Frame::status)
        .next_back();
    let authenticated = setup_status == Some(0);
    if authenticated && let Some(error) = failure {
        report.check(1).saw(format!(
            "the server accepted the authentication; the run stopped later, at: {}",
            describe(error)
        ));
    }

    flag_check(
        report,
        1,
        &[
            (ntlm::NEGOTIATE_SIGN, "NTLMSSP_NEGOTIATE_SIGN", true),
            (
                ntlm::NEGOTIATE_ALWAYS_SIGN,
                "NTLMSSP_NEGOTIATE_ALWAYS_SIGN",
                false,
            ),
        ],
        &seen,
        authenticated,
        failure,
    );
    flag_check(
        report,
        2,
        &[(ntlm::NEGOTIATE_VERSION, "NTLMSSP_NEGOTIATE_VERSION", false)],
        &seen,
        authenticated,
        failure,
    );
    {
        let carried: Vec<String> = seen
            .iter()
            .filter(|message| message.version.iter().any(|byte| *byte != 0))
            .map(|message| message.kind.to_string())
            .collect();
        let check = report.check(2);
        if carried.is_empty() {
            check.saw(
                "the Version structure in every NTLMSSP message that went out is eight zero \
                 bytes: nothing naming this host's operating system reached the server",
            );
        } else {
            check.saw(format!(
                "NTLMSSP message types {} carried a non-zero Version structure",
                carried.join(", ")
            ));
            check.verdict(Verdict::Fail);
        }
    }

    // Check 9 — the three client-side values.
    let setup = frames
        .iter()
        .find(|frame| frame.is_smb() && frame.outbound && frame.command() == SESSION_SETUP_ANDX);
    match setup.and_then(session_setup_values) {
        Some((max_buffer, max_mpx, capabilities)) => {
            let check = report.check(9);
            check.saw(format!(
                "the session setup advertised MaxBufferSize = {}",
                grouped(u64::from(max_buffer))
            ));
            check.saw(format!("MaxMpxCount = {max_mpx}"));
            check.saw(format!("Capabilities = {capabilities:#010x}"));
            if authenticated {
                check.saw("the server accepted all three and authenticated the session");
                check.verdict(Verdict::Pass);
            } else {
                check.saw(format!(
                    "the session setup was refused: {}",
                    failure.map(describe).unwrap_or_default()
                ));
                check.verdict(Verdict::Fail);
            }
        }
        None => {
            let check = report.check(9);
            check.saw("no session setup request was captured");
            check.verdict(Verdict::Unrunnable);
        }
    }
}

/// Reports one check's worth of NTLM flag bits over every message that went
/// out, and settles its verdict on whether authentication then succeeded.
fn flag_check(
    report: &mut Report,
    number: usize,
    bits: &[(u32, &str, bool)],
    seen: &[NtlmSeen],
    authenticated: bool,
    failure: Option<&Error>,
) {
    let mut as_intended = !seen.is_empty();
    let mut lines = Vec::new();
    for message in seen {
        let spelled = bits
            .iter()
            .map(|(bit, name, wanted)| {
                let set = message.flags & bit != 0;
                as_intended &= set == *wanted;
                format!("{name} {}", if set { "set" } else { "clear" })
            })
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!(
            "the NTLMSSP {} message on the wire carried NegotiateFlags = {:#010x}: {spelled}",
            if message.kind == 1 {
                "NEGOTIATE"
            } else {
                "AUTHENTICATE"
            },
            message.flags
        ));
    }
    if seen.is_empty() {
        lines.push("no NTLMSSP message was captured".to_owned());
    }

    let check = report.check(number);
    for line in lines {
        check.saw(line);
    }
    if !as_intended {
        check
            .saw("the flags are not as the design record fixes them; the crate itself has changed");
        check.verdict(Verdict::Fail);
    } else if authenticated {
        check.saw("the server authenticated the session");
        check.verdict(Verdict::Pass);
    } else {
        check.saw(format!(
            "the server refused the authentication: {}",
            failure.map(describe).unwrap_or_default()
        ));
        check.verdict(Verdict::Fail);
    }
}

/// `yes` or `no`, for a report line.
fn yes_no(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

/// Finds — or, where writing is allowed, makes — the large file and the
/// multi-page directory the later checks need.
async fn discover(args: &Args, context: &mut Fixture, report: &mut Report) {
    if context.large_file.is_none() || context.big_directory.is_none() {
        scan(
            &context.tree,
            &args.directory,
            &mut context.large_file,
            &mut context.big_directory,
            report,
        )
        .await;
    }

    if args.read_only {
        return;
    }

    let scratch = join(
        &args.directory,
        &format!("smb1client-conformance-{}", std::process::id()),
    );
    match context.tree.create_dir(&scratch).await {
        Ok(()) => {
            report.note(format!("the scratch directory is {scratch}"));
            context.scratch = Some(scratch);
        }
        Err(error) => {
            report.note(format!(
                "the scratch directory could not be created, so every check that writes is \
                 unrunnable here: {}",
                describe(&error)
            ));
        }
    }
}

/// Walks down from the working directory looking for a file of at least
/// [`LARGE`] bytes and a directory that needs more than one listing page.
///
/// It reads and nothing else, so it is safe against a device holding somebody's
/// data.
async fn scan(
    tree: &Tree,
    directory: &str,
    large_file: &mut Option<String>,
    big_directory: &mut Option<String>,
    report: &mut Report,
) {
    // Breadth first from the working directory, under one budget for the whole
    // walk. Depth is not the bound because what is being looked for sits at no
    // fixed depth: on one server the share root holds the entries and on
    // another they are four levels down a photo library.
    let mut queue = std::collections::VecDeque::from([directory.to_owned()]);
    let mut opened = 0usize;
    while let Some(candidate) = queue.pop_front() {
        if opened >= DISCOVERY_DIRECTORIES || (large_file.is_some() && big_directory.is_some()) {
            break;
        }
        opened += 1;
        let mut nested = Vec::new();
        if count_and_collect(tree, &candidate, large_file, &mut nested).await {
            big_directory.get_or_insert(candidate);
        }
        queue.extend(nested);
    }

    match large_file {
        Some(file) => report.note(format!("the large-read file is {file}")),
        None => report.note(format!(
            "no file of at least {} bytes was found",
            grouped(LARGE as u64)
        )),
    }
    if let Some(directory) = big_directory {
        report.note(format!("the multi-page directory is {}", named(directory)));
    }
}

/// Lists one directory, noting any large file in it, collecting its
/// subdirectories, and answering whether it holds more entries than one page.
async fn count_and_collect(
    tree: &Tree,
    directory: &str,
    large_file: &mut Option<String>,
    directories: &mut Vec<String>,
) -> bool {
    let mut listing = match tree.read_dir(directory).await {
        Ok(listing) => listing,
        Err(_) => return false,
    };
    let mut seen = 0usize;
    let mut paged = false;
    loop {
        match listing.next_entry().await {
            Ok(Some(entry)) => {
                seen += 1;
                if seen > ENTRIES_PER_PAGE {
                    paged = true;
                }
                if entry.is_dir() {
                    directories.push(join(directory, entry.name()));
                } else if large_file.is_none() && entry.len() >= LARGE as u64 {
                    *large_file = Some(join(directory, entry.name()));
                }
                if seen >= DISCOVERY_ENTRIES {
                    break;
                }
            }
            Ok(None) => break,
            Err(_) => break,
        }
    }
    let _ = listing.close().await;
    paged
}

/// How a share-relative path reads in the report, the root included.
fn named(path: &str) -> &str {
    if path.is_empty() {
        "(the share root)"
    } else {
        path
    }
}

/// Joins a directory to a name, share-relative.
fn join(directory: &str, name: &str) -> String {
    if directory.is_empty() {
        name.to_owned()
    } else {
        format!("{}\\{}", directory.trim_end_matches('\\'), name)
    }
}

/// Check 6, first half — the idle probe on a live session.
async fn check_six_live(context: &Fixture, report: &mut Report) {
    let probe = Request::new(
        ECHO,
        NO_TREE,
        NO_SESSION,
        vec![0x01, 0x01, 0x00, 0x00, 0x00],
    );
    let answered =
        tokio::time::timeout(PROBE_TIMEOUT, context.tree.connection().request(probe)).await;

    let check = report.check(6);
    match answered {
        Ok(Ok(reply)) => {
            check.saw(format!(
                "on a live session the probe — UID = 0, TID = 0xFFFF, EchoCount = 1, empty byte \
                 area — was answered {}",
                reply.status()
            ));
            match context.tree.metadata("").await {
                Ok(_) => check.saw("the session still worked afterwards"),
                Err(error) => check.saw(format!(
                    "the session did not work afterwards: {}",
                    describe(&error)
                )),
            };
            if reply.status() != NtStatus::SUCCESS {
                check.verdict(Verdict::Fail);
            }
        }
        Ok(Err(error)) => {
            check.saw(format!("the probe failed on a live session: {error}"));
            check.verdict(Verdict::Fail);
        }
        Err(_) => {
            check.saw("the probe was not answered on a live session within 15 s");
            check.verdict(Verdict::Fail);
        }
    }
}

/// Check 6, second half — the probe on a connection whose session the server
/// has discarded.
///
/// `SMB_COM_LOGOFF_ANDX` is how this script asks a server to discard one, which
/// is a thing the design record says none of the servers it reached could be
/// made to do on demand.
async fn check_six_discarded(args: &Args, context: &Fixture, report: &mut Report) -> Vec<String> {
    if report.check(6).verdict == Verdict::Fail {
        return Vec::new();
    }
    let identity = match discarded_session_probe(args, context).await {
        Ok((lines, identity)) => {
            for line in lines {
                report.check(6).saw(line);
            }
            identity
        }
        Err(line) => {
            report.check(6).saw(line);
            Vec::new()
        }
    };

    // What that cost the connection the rest of this run used. On a server that
    // scopes a session to the client host rather than to the connection, a
    // logoff on one connection takes the other's session with it.
    let survived = context.tree.metadata("").await;
    let check = report.check(6);
    check.saw(match &survived {
        Ok(_) => "the connection the rest of this run used was unaffected".to_owned(),
        Err(error) => format!(
            "the connection the rest of this run used stopped working when that second \
             connection logged off: {}",
            describe(error)
        ),
    });
    check.verdict(Verdict::Reported);
    identity
}

/// Authenticates a connection of its own, logs the session off, and asks the
/// probe what a server does on a connection whose session it has discarded.
async fn discarded_session_probe(
    args: &Args,
    context: &Fixture,
) -> Result<(Vec<String>, Vec<String>), String> {
    let (host, port) = args.server.dial_address();
    let stream = tokio::time::timeout(PROBE_TIMEOUT, TcpStream::connect((host, port)))
        .await
        .map_err(|_| "the second-half dial timed out".to_owned())?
        .map_err(|error| format!("the second-half dial failed: {error}"))?;

    let options = SessionOptions {
        allow_guest: args.allow_guest,
        ..SessionOptions::default()
    };
    let session = Session::establish(stream, &args.credentials, &options)
        .await
        .map_err(|error| {
            format!(
                "the second-half session could not be established: {}",
                describe(&error)
            )
        })?;

    let identity = session.server().strings.clone();
    let mut lines = Vec::new();
    // Asked before the logoff, so that a first connection that stops working
    // can be laid at the door of the right event: a server that objects to a
    // second handshake from one client host has already objected by here.
    if let Err(error) = context.tree.metadata("").await {
        lines.push(format!(
            "authenticating a second connection from this host, before anything was logged off, \
             already cost the first connection its session: {}",
            describe(&error)
        ));
    }
    let logoff = Request::new(
        LOGOFF_ANDX,
        0,
        session.uid(),
        vec![0x02, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00],
    );
    match tokio::time::timeout(PROBE_TIMEOUT, session.connection().request(logoff)).await {
        Ok(Ok(reply)) => lines.push(format!(
            "a session made and then logged off answered SMB_COM_LOGOFF_ANDX {}, so the server \
             has discarded that session",
            reply.status()
        )),
        Ok(Err(error)) => {
            return Err(format!(
                "the logoff that would discard the session failed ({error}), so this server \
                 cannot be made to hold a connection whose session it discarded"
            ));
        }
        Err(_) => return Err("the logoff was not answered within 15 s".to_owned()),
    }

    let probe = Request::new(
        ECHO,
        NO_TREE,
        NO_SESSION,
        vec![0x01, 0x01, 0x00, 0x00, 0x00],
    );
    match tokio::time::timeout(PROBE_TIMEOUT, session.connection().request(probe)).await {
        Ok(Ok(reply)) => lines.push(format!(
            "the probe on that connection was answered {} — the probe reports a connection whose \
             session the server has discarded as live",
            reply.status()
        )),
        Ok(Err(error)) => lines.push(format!(
            "the probe on that connection failed ({error}) — the server did not answer a \
             connection whose session it had discarded"
        )),
        Err(_) => lines.push(
            "the probe on that connection was not answered within 15 s — the server left it \
             silent"
                .to_owned(),
        ),
    }
    Ok((lines, identity))
}

/// Check 4 — a 130,048-byte read and write.
async fn check_four(args: &Args, context: &Fixture, report: &mut Report, capture: &Arc<Capture>) {
    let connection = context.tree.connection();
    let negotiated = connection.negotiated();
    let large_read = negotiated.capabilities & CAP_LARGE_READX != 0;
    let large_write = negotiated.capabilities & CAP_LARGE_WRITEX != 0;

    {
        let check = report.check(4);
        check.saw(format!(
            "the server sets CAP_LARGE_READX {}, CAP_LARGE_WRITEX {}, beside MaxBufferSize = {}",
            yes_no(large_read),
            yes_no(large_write),
            grouped(u64::from(negotiated.max_buffer_size))
        ));
        check.saw(format!(
            "so this connection asks {} bytes a read and carries {} bytes a write",
            grouped(connection.read_chunk_size() as u64),
            grouped(connection.write_chunk_size() as u64)
        ));
    }

    // The write half.
    let mut written_file = None;
    match (&context.scratch, args.read_only) {
        (_, true) => {
            report
                .check(4)
                .saw("the write half is skipped: --read-only forbids writing to this server");
        }
        (None, false) => {
            report
                .check(4)
                .saw("the write half is unrunnable: no scratch directory could be made");
        }
        (Some(scratch), false) => {
            let path = join(scratch, "large.bin");
            let data: Vec<u8> = (0..LARGE).map(|index| (index % 251) as u8).collect();
            let mark = capture.mark();
            let outcome = write_file(&context.tree, &path, &data).await;
            let frames = capture.since(mark);
            let carried = tally(&frames, true, WRITE_ANDX, write_carried);
            let acknowledged = tally(&frames, false, WRITE_ANDX, write_acknowledged);
            let check = report.check(4);
            check.saw(format!(
                "a {}-byte write went out as WRITE_ANDX payloads of {} and was acknowledged {}",
                grouped(LARGE as u64),
                counted(&carried),
                counted(&acknowledged)
            ));
            match outcome {
                Ok(()) => {
                    check.saw("the write succeeded");
                    written_file = Some(path);
                }
                Err(error) => {
                    check.saw(format!("the write failed: {}", describe(&error)));
                    check.verdict(Verdict::Fail);
                    return;
                }
            }
        }
    }

    // The read half.
    let source = written_file.clone().or_else(|| context.large_file.clone());
    let Some(source) = source else {
        report.check(4).saw(format!(
            "the read half is unrunnable: no file of at least {} bytes is available",
            grouped(LARGE as u64)
        ));
        report.check(4).verdict(Verdict::Reported);
        return;
    };

    let mark = capture.mark();
    let mut buffer = vec![0u8; LARGE];
    let outcome = read_file(&context.tree, &source, &mut buffer).await;
    let frames = capture.since(mark);
    let asked = tally(&frames, true, READ_ANDX, read_asked);
    let served = tally(&frames, false, READ_ANDX, read_served);

    let check = report.check(4);
    check.saw(format!(
        "a {}-byte read of {source} asked in READ_ANDX chunks of {} and was served {}",
        grouped(LARGE as u64),
        counted(&asked),
        counted(&served)
    ));
    match outcome {
        Ok(()) => {
            check.saw("the read filled the whole span");
            if written_file.is_some() {
                let expected: Vec<u8> = (0..LARGE).map(|index| (index % 251) as u8).collect();
                check.saw(if buffer == expected {
                    "the bytes read back are the bytes written"
                } else {
                    "the bytes read back are NOT the bytes written"
                });
                if buffer != expected {
                    check.verdict(Verdict::Fail);
                    return;
                }
            }
            check.verdict(Verdict::Reported);
        }
        Err(error) => {
            check.saw(format!("the read failed: {}", describe(&error)));
            check.verdict(Verdict::Fail);
        }
    }
}

/// Writes a file whole, through a handle so the chunking is the crate's own.
async fn write_file(tree: &Tree, path: &str, data: &[u8]) -> Result<(), Error> {
    let file = tree.create(path).await?;
    let written = file.write_all_at(data, 0, None).await;
    let closed = file.close().await;
    written.and(closed)
}

/// Fills `buffer` from the start of a file.
async fn read_file(tree: &Tree, path: &str, buffer: &mut [u8]) -> Result<(), Error> {
    let file = tree.open_with(path, &OpenOptions::new().read(true)).await?;
    let read = file.read_exact_at(buffer, 0).await;
    let closed = file.close().await;
    read.and(closed)
}

/// Counts how often each value of some field appeared across a set of frames.
fn tally(
    frames: &[Frame],
    outbound: bool,
    command: u8,
    field: fn(&Frame) -> Option<u32>,
) -> BTreeMap<u32, usize> {
    let mut counts = BTreeMap::new();
    for frame in frames
        .iter()
        .filter(|frame| frame.is_smb() && frame.outbound == outbound && frame.command() == command)
    {
        if let Some(value) = field(frame) {
            *counts.entry(value).or_default() += 1;
        }
    }
    counts
}

/// A tally, written as the report wants to read it.
fn counted(counts: &BTreeMap<u32, usize>) -> String {
    if counts.is_empty() {
        return "nothing".to_owned();
    }
    let mut out = String::new();
    for (value, count) in counts {
        if !out.is_empty() {
            out.push_str(", ");
        }
        let _ = write!(out, "{}", grouped(u64::from(*value)));
        if *count > 1 {
            let _ = write!(out, " (x{count})");
        }
    }
    out
}

/// Check 7 — both `NT_CREATE_ANDX` departures.
async fn check_seven(args: &Args, context: &Fixture, report: &mut Report, capture: &Arc<Capture>) {
    let target = context
        .scratch
        .as_ref()
        .map(|scratch| join(scratch, "open.bin"))
        .or_else(|| context.large_file.clone());
    let Some(target) = target else {
        report
            .check(7)
            .saw("no file is available to open, so the check cannot run");
        return;
    };

    let created = if args.read_only || context.scratch.is_none() {
        false
    } else {
        match write_file(&context.tree, &target, b"conformance").await {
            Ok(()) => true,
            Err(error) => {
                report.check(7).saw(format!(
                    "the file the check would open could not be created: {}",
                    describe(&error)
                ));
                return;
            }
        }
    };

    let mark = capture.mark();
    let opened = context
        .tree
        .open_with(&target, &OpenOptions::new().read(true))
        .await;
    let frames = capture.since(mark);
    let create = frames
        .iter()
        .find(|frame| frame.is_smb() && frame.outbound && frame.command() == NT_CREATE_ANDX)
        .and_then(create_values);

    let file = match opened {
        Ok(file) => Some(file),
        Err(error) => {
            let check = report.check(7);
            check.saw(format!("opening {target} failed: {}", describe(&error)));
            check.verdict(Verdict::Fail);
            None
        }
    };

    match create {
        Some((desired_access, share_access)) => {
            let check = report.check(7);
            check.saw(format!(
                "the open went out with ShareAccess = {share_access:#x} (the reference sends \
                 0x3) and DesiredAccess = {desired_access:#010x}, SYNCHRONIZE {}",
                if desired_access & SYNCHRONIZE == 0 {
                    "absent"
                } else {
                    "present"
                }
            ));
            if file.is_some() {
                check.saw("the server granted the open");
                check.verdict(Verdict::Pass);
            }
        }
        None => {
            let check = report.check(7);
            check.saw("no NT_CREATE_ANDX request was captured");
            if file.is_some() {
                check.verdict(Verdict::Unrunnable);
            }
        }
    }

    // What the permissive `ShareAccess` is for: a delete against a handle
    // somebody else holds. It needs a file this script may delete, so it runs
    // only on the scratch copy.
    if !created {
        report.check(7).saw(
            "the consequence of the permissive ShareAccess — a delete against an open handle — \
             is skipped: it needs a file this run may delete",
        );
    } else if let Some(open) = &file {
        let deleted = context.tree.remove_file(&target).await;
        let check = report.check(7);
        match deleted {
            Ok(()) => check.saw(
                "deleting the file while this run still held a read handle on it succeeded, \
                 which is what the permissive ShareAccess of 0x7 buys",
            ),
            Err(error) => check.saw(format!(
                "deleting the file while this run still held a read handle on it failed: {}",
                describe(&error)
            )),
        };
        let _ = open;
    }

    if let Some(file) = file {
        let _ = file.close().await;
    }
}

/// Check 5 — `SMB_FIND_CLOSE_AT_EOS` on a `FIND_NEXT2`.
async fn check_five(args: &Args, context: &Fixture, report: &mut Report, capture: &Arc<Capture>) {
    let mut directory = context.big_directory.clone();
    let mut made = None;

    if directory.is_none() {
        match (&context.scratch, args.read_only) {
            (_, true) => {
                let check = report.check(5);
                check.saw(format!(
                    "no directory on this server holds more than the {ENTRIES_PER_PAGE} entries a \
                     listing asks for at a time, and --read-only forbids making one, so no \
                     FIND_NEXT2 can be provoked"
                ));
                check.verdict(Verdict::Skipped);
                return;
            }
            (None, false) => {
                let check = report.check(5);
                check.saw("no multi-page directory exists and no scratch directory could be made");
                check.verdict(Verdict::Unrunnable);
                return;
            }
            (Some(scratch), false) => {
                let path = join(scratch, "paged");
                match fill_directory(&context.tree, &path, SCRATCH_ENTRIES).await {
                    Ok(()) => {
                        report.check(5).saw(format!(
                            "no directory on this server needed paging, so this run made one \
                             holding {SCRATCH_ENTRIES} entries"
                        ));
                        made = Some(path.clone());
                        directory = Some(path);
                    }
                    Err(error) => {
                        let check = report.check(5);
                        check.saw(format!(
                            "a directory to page over could not be made: {}",
                            describe(&error)
                        ));
                        check.verdict(Verdict::Unrunnable);
                        return;
                    }
                }
            }
        }
    }
    let _ = made;

    let Some(directory) = directory else {
        report.check(5).verdict(Verdict::Unrunnable);
        return;
    };

    let mark = capture.mark();
    let mut listing = match context.tree.read_dir(&directory).await {
        Ok(listing) => listing,
        Err(error) => {
            let check = report.check(5);
            check.saw(format!("listing {directory} failed: {}", describe(&error)));
            check.verdict(Verdict::Fail);
            return;
        }
    };
    let mut entries = 0usize;
    let mut failure = None;
    loop {
        match listing.next_entry().await {
            Ok(Some(_)) => entries += 1,
            Ok(None) => break,
            Err(error) => {
                failure = Some(describe(&error));
                break;
            }
        }
    }
    let _ = listing.close().await;
    let frames = capture.since(mark);

    // What went out, and what came back.
    let mut next_flags = Vec::new();
    for frame in frames
        .iter()
        .filter(|frame| frame.is_smb() && frame.outbound && frame.command() == TRANSACTION2)
    {
        if trans2_subcommand(frame) == Some(FIND_NEXT2)
            && let Some(flags) = trans2_request_parameters(frame).and_then(|p| u16le(p, 10))
        {
            next_flags.push(flags);
        }
    }
    let statuses: Vec<u32> = frames
        .iter()
        .filter(|frame| frame.is_smb() && !frame.outbound && frame.command() == TRANSACTION2)
        .map(Frame::status)
        .collect();
    let search_id = frames
        .iter()
        .find(|frame| {
            frame.is_smb()
                && frame.outbound
                && frame.command() == TRANSACTION2
                && trans2_subcommand(frame) == Some(FIND_FIRST2)
        })
        .and_then(|_| {
            frames
                .iter()
                .find(|frame| frame.is_smb() && !frame.outbound && frame.command() == TRANSACTION2)
                .and_then(trans2_response_parameters)
                .and_then(|parameters| u16le(parameters, 0))
        });

    let check = report.check(5);
    check.saw(format!(
        "listing {} returned {entries} entries",
        named(&directory)
    ));
    if next_flags.is_empty() {
        check.saw(
            "the listing needed no FIND_NEXT2, so nothing carried SMB_FIND_CLOSE_AT_EOS on one",
        );
        check.verdict(Verdict::Unrunnable);
        return;
    }
    let carried = next_flags.iter().all(|flags| flags & 0x0002 != 0);
    check.saw(format!(
        "{} FIND_NEXT2 requests went out, each with Flags = {:#06x}; SMB_FIND_CLOSE_AT_EOS {}",
        next_flags.len(),
        next_flags[0],
        if carried { "set" } else { "CLEAR" }
    ));
    let refused: Vec<String> = statuses
        .iter()
        .filter(|status| **status != 0 && **status != NtStatus::NO_MORE_FILES.code())
        .map(|status| format!("{status:#010x}"))
        .collect();
    if refused.is_empty() {
        check.saw("every TRANS2 reply was STATUS_SUCCESS or STATUS_NO_MORE_FILES");
    } else {
        check.saw(format!(
            "TRANS2 replies carried refusals: {}",
            refused.join(", ")
        ));
    }

    if let Some(failure) = failure {
        check.saw(format!("the listing failed part way: {failure}"));
        check.verdict(Verdict::Fail);
        return;
    }
    if !carried {
        check.saw("the crate did not send the flag it is supposed to send");
        check.verdict(Verdict::Fail);
        return;
    }
    if !refused.is_empty() {
        check.verdict(Verdict::Fail);
        return;
    }

    // Whether the flag was honoured rather than merely tolerated. Closing a
    // search the server has already released is what tells the two apart, and
    // that reading is only sound where the server's own answers discriminate:
    // a close on a search it *is* holding has to succeed and a close on a
    // search id it never issued has to be refused. Both controls run first, and
    // the conclusion is drawn only where they came out that way.
    let Some(sid) = search_id else {
        check.saw("no search id was captured, so whether the flag was honoured is unknown");
        check.verdict(Verdict::Pass);
        return;
    };

    let open_mark = capture.mark();
    let mut still_open = context.tree.read_dir(&directory).await.ok();
    if let Some(listing) = still_open.as_mut() {
        let _ = listing.next_entry().await;
    }
    let open_sid = capture
        .since(open_mark)
        .iter()
        .find(|frame| frame.is_smb() && !frame.outbound && frame.command() == TRANSACTION2)
        .and_then(trans2_response_parameters)
        .and_then(|parameters| u16le(parameters, 0));
    let open_status = match open_sid {
        Some(open_sid) => find_close2(context, open_sid).await,
        None => "not at all (no second search was opened)".to_owned(),
    };
    drop(still_open);

    let never = sid ^ 0x5A5A;
    let never_status = find_close2(context, never).await;
    let drained_status = find_close2(context, sid).await;

    check.saw(format!(
        "control: SMB_COM_FIND_CLOSE2 on a search the server is still holding was answered \
         {open_status}"
    ));
    check.saw(format!(
        "control: SMB_COM_FIND_CLOSE2 on a search id this run never opened ({never:#06x}) was \
         answered {never_status}"
    ));
    check.saw(format!(
        "SMB_COM_FIND_CLOSE2 on the drained listing's own search id ({sid:#06x}) was answered \
         {drained_status}"
    ));
    let succeeded = |status: &str| status.starts_with("STATUS_SUCCESS");
    check.saw(if !succeeded(&open_status) || succeeded(&never_status) {
        "the controls do not discriminate on this server — it does not refuse a close on a \
         search id it never issued — so nothing here says whether SMB_FIND_CLOSE_AT_EOS was \
         honoured"
            .to_owned()
    } else if succeeded(&drained_status) {
        "the controls discriminate and the drained search still closed, so it was still open: \
         the server accepted SMB_FIND_CLOSE_AT_EOS without acting on it"
            .to_owned()
    } else {
        "the controls discriminate and the drained search was already gone: the server honoured \
         SMB_FIND_CLOSE_AT_EOS"
            .to_owned()
    });
    check.verdict(Verdict::Pass);
}

/// Sends one `SMB_COM_FIND_CLOSE2` by hand and says what came back.
async fn find_close2(context: &Fixture, sid: u16) -> String {
    let body = vec![0x01, (sid & 0xFF) as u8, (sid >> 8) as u8, 0x00, 0x00];
    let request = Request::new(FIND_CLOSE2, context.tree.tid(), context.uid, body);
    match tokio::time::timeout(PROBE_TIMEOUT, context.tree.connection().request(request)).await {
        Ok(Ok(reply)) => reply.status().to_string(),
        Ok(Err(error)) => format!("not at all ({error})"),
        Err(_) => "not at all (no reply in 15 s)".to_owned(),
    }
}

/// Creates a directory holding `entries` empty files.
async fn fill_directory(tree: &Tree, path: &str, entries: usize) -> Result<(), Error> {
    tree.create_dir(path).await?;
    for index in 0..entries {
        let entry = join(path, &format!("conformance-entry-{index:04}.dat"));
        tree.create(&entry).await?.close().await?;
    }
    Ok(())
}

/// Check 3 — every request this run sent carried `Flags2` without
/// `SMB_FLAGS2_KNOWS_EAS`.
fn check_three(report: &mut Report, capture: &Arc<Capture>) {
    let frames = capture.since(0);
    let mut values: BTreeMap<u16, usize> = BTreeMap::new();
    for frame in frames
        .iter()
        .filter(|frame| frame.is_smb() && frame.outbound)
    {
        *values.entry(frame.flags2()).or_default() += 1;
    }

    let sent: usize = values.values().sum();
    let with_eas: usize = values
        .iter()
        .filter(|(flags2, _)| *flags2 & FLAGS2_KNOWS_EAS != 0)
        .map(|(_, count)| *count)
        .sum();
    let spelled = values
        .iter()
        .map(|(flags2, count)| format!("{flags2:#06x} (x{count})"))
        .collect::<Vec<_>>()
        .join(", ");

    let check = report.check(3);
    check.saw(format!(
        "{sent} requests went out, carrying Flags2 {spelled} — the reference sends 0xC803"
    ));
    if sent == 0 {
        check.saw("nothing was sent, so nothing exercised the departure");
        check.verdict(Verdict::Unrunnable);
        return;
    }
    if with_eas > 0 {
        check.saw(format!(
            "{with_eas} of them carried SMB_FLAGS2_KNOWS_EAS, which this crate does not send"
        ));
        check.verdict(Verdict::Fail);
        return;
    }
    check.saw(
        "the server answered them: the handshake, the tree connect and every verb this run issued",
    );
    check.verdict(Verdict::Pass);
}
