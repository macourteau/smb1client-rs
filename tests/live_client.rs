//! The caching layer against a real server.
//!
//! `#[ignore]`d and driven from the environment like the rest of the acceptance
//! suite: `SMB1_TEST_SERVER`, `SMB1_TEST_SHARE`, `SMB1_TEST_USER` and
//! `SMB1_TEST_PASSWORD`, run with `cargo test -- --include-ignored`.
//!
//! **`SMB_COM_ECHO` is one of only two wire paths in this crate with no offline
//! oracle**: the reference library sends none, no fixture carries one, and the
//! frame this crate sends is written from the specification. So the first test
//! below is a conformance check rather than a regression test — it asks a real
//! server whether it answers an echo carrying `UID = 0` and `TID = 0xFFFF`, and
//! whether the session still works afterwards.
//!
//! Nothing here writes to the server except through the scratch directory the
//! filesystem suite owns, so this file is safe to point at a device holding
//! somebody's data.

use std::time::Duration;

use smb1client::connection::Request;
use smb1client::{Client, ClientConfig, Credentials, NtStatus, Server, Session, SessionOptions};

/// `SMB_COM_ECHO`.
const ECHO: u8 = 0x2B;

struct Target {
    server: Server,
    share: String,
    credentials: Credentials,
    allow_guest: bool,
}

fn target() -> Option<Target> {
    let server = std::env::var("SMB1_TEST_SERVER").ok()?;
    let share = std::env::var("SMB1_TEST_SHARE").unwrap_or_else(|_| "testshare".to_owned());
    let user = std::env::var("SMB1_TEST_USER").unwrap_or_default();
    let password = std::env::var("SMB1_TEST_PASSWORD").unwrap_or_default();
    let domain = std::env::var("SMB1_TEST_DOMAIN").unwrap_or_default();
    Some(Target {
        server: server.parse().expect("SMB1_TEST_SERVER names a server"),
        share,
        credentials: Credentials::new(user, password).with_domain(domain),
        allow_guest: std::env::var("SMB1_TEST_ALLOW_GUEST").is_ok(),
    })
}

fn config(target: &Target) -> ClientConfig {
    ClientConfig {
        allow_guest: target.allow_guest,
        ..ClientConfig::new(target.credentials.clone())
    }
}

/// The probe's own frame, sent by hand on a session this test built, so that
/// what the server answers is visible rather than inferred.
///
/// **What a wrong answer looks like**: any status but success, which would mean
/// the probe evicts every connection it exists to vouch for. `UID = 0` and
/// `TID = 0xFFFF` are the reasoned values the conformance script carries, and
/// this is where a server is asked about them.
#[tokio::test]
#[ignore = "needs a live SMB1 server; set SMB1_TEST_SERVER"]
async fn a_live_server_answers_the_probe_and_keeps_the_session() {
    let Some(target) = target() else {
        eprintln!("SMB1_TEST_SERVER is unset; nothing to talk to");
        return;
    };
    let (host, port) = target.server.dial_address();
    let stream = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect((host, port)),
    )
    .await
    .expect("the dial timed out")
    .expect("the dial failed");
    let session = Session::establish(
        stream,
        &target.credentials,
        &SessionOptions {
            allow_guest: target.allow_guest,
            ..SessionOptions::default()
        },
    )
    .await
    .expect("the handshake succeeded");

    // `WordCount = 1`, `EchoCount = 1`, `ByteCount = 0` — the whole of the
    // probe's body, written out here rather than reached through the crate's
    // own encoder, so that this test says what went on the wire.
    let reply = session
        .connection()
        .request(Request::new(ECHO, 0xFFFF, 0, vec![1, 1, 0, 0, 0]))
        .await
        .expect("the echo was answered");
    println!("{}: echo answered {:?}", target.server, reply.status());
    assert_eq!(
        reply.status(),
        NtStatus::SUCCESS,
        "a server that refuses the probe would have every idle connection evicted"
    );

    // And the session is unharmed by an echo that claimed neither of its ids.
    let tree = smb1client::Tree::connect(
        session,
        &format!(r"{}\{}", target.server.unc_name(), target.share),
        "?????",
    )
    .await
    .expect("the session still works after the probe");
    tree.close().await.expect("the tree disconnected");
}

/// One client, one connection, and the tree cache on top of it.
///
/// **What a wrong implementation does**: dials again for the second call, or
/// connects the tree again — both of which cost a round trip nobody asked for,
/// and the second of which leaks a server-side handle per call.
#[tokio::test]
#[ignore = "needs a live SMB1 server; set SMB1_TEST_SERVER"]
async fn a_live_client_caches_its_connection_and_its_tree() {
    let Some(target) = target() else {
        eprintln!("SMB1_TEST_SERVER is unset; nothing to talk to");
        return;
    };
    let client = Client::new(config(&target));
    let path = format!(r"\\{}\{}", target.server, target.share)
        .parse()
        .expect("a valid UNC path");

    let first = client.tree(&path).await.expect("the first tree");
    let mut listing = first.read_dir("").await.expect("the share root listed");
    let mut entries = 0;
    while listing
        .next_entry()
        .await
        .expect("a page decoded")
        .is_some()
    {
        entries += 1;
    }
    listing.close().await.expect("the search was released");

    let second = client.tree(&path).await.expect("the second tree");
    assert_eq!(
        first.tid(),
        second.tid(),
        "the same share on the same server is the same tree"
    );
    println!(
        "{}: {entries} entries at the root, tid {}",
        target.server,
        first.tid()
    );

    let shares = client
        .list_shares(&target.server)
        .await
        .expect("the shares enumerated");
    println!("{}: {} shares", target.server, shares.len());
    for share in shares.iter().take(10) {
        println!(
            "  {} {:?} {:?}",
            share.name, share.kind.service, share.comment
        );
    }
    assert!(!shares.is_empty(), "a server offers at least IPC$");

    drop(first);
    drop(second);
    client.close().await.expect("the goodbye was accepted");
}

/// The idle probe on the path it exists for, at an overall deadline short
/// enough to reach in real time.
///
/// **What a wrong implementation does**: sends the probe under the session's
/// own ids, or evicts on an answer it misread — either of which shows up here
/// as a re-dial, which the tree id is what reports.
#[tokio::test]
#[ignore = "needs a live SMB1 server; set SMB1_TEST_SERVER"]
async fn a_live_idle_connection_is_probed_and_reused() {
    let Some(target) = target() else {
        eprintln!("SMB1_TEST_SERVER is unset; nothing to talk to");
        return;
    };
    let client = Client::new(ClientConfig {
        // One second of idleness is what makes the probe reachable without a
        // virtual clock. It bounds a request's whole life too, which is why
        // every operation below is a single round trip.
        overall_deadline: Duration::from_secs(1),
        ..config(&target)
    });
    let path = format!(r"\\{}\{}", target.server, target.share)
        .parse()
        .expect("a valid UNC path");

    let first = client.tree(&path).await.expect("the first tree");
    tokio::time::sleep(Duration::from_millis(1_500)).await;

    let second = client.tree(&path).await.expect("the probe answered");
    assert_eq!(
        first.tid(),
        second.tid(),
        "the probe vouched for the connection rather than evicting it"
    );
    second
        .exists("no-such-file-c0ffee.txt")
        .await
        .expect("the connection works after the probe");

    drop(first);
    drop(second);
    client.close().await.expect("the goodbye was accepted");
}
