//! The first thing in this crate that talks to a real server.
//!
//! It is `#[ignore]`d and reads its target from the environment, like the rest
//! of the acceptance suite: `cargo test -- --include-ignored` with
//! `SMB1_TEST_SERVER`, `SMB1_TEST_USER` and `SMB1_TEST_PASSWORD` set runs it.
//! Nothing here is a CI job against anything but the pinned container.
//!
//! What it proves is what no scripted response can: that a real server accepts
//! the nine NTLM flags, the DER this crate emits, the `mechListMIC` it computes
//! and the `SESSION_SETUP_ANDX` alignment it lands the strings on. Three of
//! those are untested wire changes against every server the campaign reached.

use std::time::Duration;

use smb1client::{Credentials, Session, SessionOptions};

#[path = "live_lock/mod.rs"]
mod live_lock;

fn target() -> Option<(String, Credentials, bool)> {
    let server = std::env::var("SMB1_TEST_SERVER").ok()?;
    let user = std::env::var("SMB1_TEST_USER").unwrap_or_default();
    let password = std::env::var("SMB1_TEST_PASSWORD").unwrap_or_default();
    let domain = std::env::var("SMB1_TEST_DOMAIN").unwrap_or_default();
    let allow_guest = std::env::var("SMB1_TEST_ALLOW_GUEST").is_ok();
    let server = if server.contains(':') {
        server
    } else {
        format!("{server}:445")
    };
    Some((
        server,
        Credentials::new(user, password).with_domain(domain),
        allow_guest,
    ))
}

/// Negotiate and session setup against a live server, and nothing else.
///
/// Authenticating and disconnecting is the whole test. It touches no share and
/// creates no file, which is what makes it safe to point at a real device.
#[tokio::test]
#[ignore = "needs a live SMB1 server; set SMB1_TEST_SERVER"]
async fn a_live_server_authenticates() {
    let _dial = live_lock::one_at_a_time().await;
    let Some((server, credentials, allow_guest)) = target() else {
        eprintln!("SMB1_TEST_SERVER is unset; nothing to talk to");
        return;
    };

    let stream = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(&server),
    )
    .await
    .unwrap_or_else(|_| panic!("{server}: the dial timed out"))
    .unwrap_or_else(|error| panic!("{server}: {error}"));

    let options = SessionOptions {
        allow_guest,
        ..SessionOptions::default()
    };
    let session = Session::establish(stream, &credentials, &options)
        .await
        .unwrap_or_else(|error| panic!("{server}: {error}"));

    let negotiated = session.negotiated();
    let info = session.server();
    println!(
        "{server}: authenticated as uid {uid}\n  \
         MaxBufferSize = {buffer}\n  \
         MaxMpxCount   = {mpx} (admission limit {limit})\n  \
         Capabilities  = {capabilities:#010x}\n  \
         SecurityMode  = {mode:#04x}\n  \
         guest         = {guest}\n  \
         server says   = {strings:?}",
        uid = session.uid(),
        buffer = negotiated.max_buffer_size,
        mpx = negotiated.max_mpx_count,
        limit = negotiated.admission_limit(),
        capabilities = negotiated.capabilities,
        mode = info.security_mode,
        guest = info.guest,
        strings = info.strings,
    );

    // The floor the handshake enforced, restated as an assertion so a server
    // that somehow got past it fails here rather than later.
    assert!(negotiated.max_buffer_size >= smb1client::session::MIN_MAX_BUFFER_SIZE);
    assert_eq!(
        negotiated.capabilities & 0x8000_0000,
        0x8000_0000,
        "CAP_EXTENDED_SECURITY is what makes the SPNEGO session setup work at all"
    );
    assert!(!info.guest || allow_guest);
}
