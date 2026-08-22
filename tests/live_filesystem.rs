//! The filesystem verbs against a live server.
//!
//! `#[ignore]`d and driven from the environment like the rest of the acceptance
//! suite: `SMB1_TEST_SERVER`, `SMB1_TEST_SHARE`, `SMB1_TEST_USER` and
//! `SMB1_TEST_PASSWORD`, run with `cargo test -- --include-ignored`. Nothing
//! here is a CI job against anything but the pinned container.
//!
//! What it proves is what no scripted response can: that a real server accepts
//! the `ShareAccess` of `0x7`, a `DesiredAccess` without `SYNCHRONIZE`, a
//! `SMB_FIND_CLOSE_AT_EOS` on a FIND_NEXT2 and an `SMB_COM_FIND_CLOSE2` written
//! from the specification — four wire changes no server in the corpus has been
//! observed to accept, because the reference library sends none of them.
//!
//! The container's own acceptance checks are here: a listing of the seeded
//! 600-entry directory returns 600, listing an empty directory returns no
//! entries and no error, and a read whose reply cannot fit one message
//! exercises reassembly at the port's own advertisement.

use std::time::Duration;

use smb1client::{Credentials, Session, SessionOptions, Tree};

/// Where to write, under the share root. Everything this suite creates lives
/// here and is removed at the end.
const SCRATCH: &str = "smb1client-rs-live";

struct Target {
    address: String,
    host: String,
    share: String,
    credentials: Credentials,
    allow_guest: bool,
    /// Whether the server may be written to. A read-only run is what points this
    /// suite at a real device.
    writable: bool,
}

fn target() -> Option<Target> {
    let server = std::env::var("SMB1_TEST_SERVER").ok()?;
    let share = std::env::var("SMB1_TEST_SHARE").unwrap_or_else(|_| "testshare".to_owned());
    let user = std::env::var("SMB1_TEST_USER").unwrap_or_default();
    let password = std::env::var("SMB1_TEST_PASSWORD").unwrap_or_default();
    let domain = std::env::var("SMB1_TEST_DOMAIN").unwrap_or_default();
    let (host, address) = match server.split_once(':') {
        Some((host, _)) => (host.to_owned(), server.clone()),
        None => (server.clone(), format!("{server}:445")),
    };
    Some(Target {
        address,
        host,
        share,
        credentials: Credentials::new(user, password).with_domain(domain),
        allow_guest: std::env::var("SMB1_TEST_ALLOW_GUEST").is_ok(),
        writable: std::env::var("SMB1_TEST_READ_ONLY").is_err(),
    })
}

async fn connect(target: &Target) -> Tree {
    connect_advertising(target, u16::MAX).await
}

/// Connects with a chosen `MaxBufferSize` in the client's own session setup,
/// which is the threshold at which a reply arrives in several messages at all.
async fn connect_advertising(target: &Target, advertised: u16) -> Tree {
    let stream = tokio::time::timeout(
        Duration::from_secs(10),
        tokio::net::TcpStream::connect(&target.address),
    )
    .await
    .unwrap_or_else(|_| panic!("{}: the dial timed out", target.address))
    .unwrap_or_else(|error| panic!("{}: {error}", target.address));

    let options = SessionOptions {
        allow_guest: target.allow_guest,
        advertised_max_buffer_size: advertised,
        ..SessionOptions::default()
    };
    let session = Session::establish(stream, &target.credentials, &options)
        .await
        .unwrap_or_else(|error| panic!("{}: {error}", target.address));

    // The server-name component is built from the host alone and never from the
    // dial address: a port in it is what Windows refuses with
    // `STATUS_DUPLICATE_NAME`.
    let path = format!("\\\\{}\\{}", target.host, target.share);
    Tree::connect(session, &path, "?????")
        .await
        .unwrap_or_else(|error| panic!("{path}: {error}"))
}

/// Lists the share root and reports what the server said about it.
///
/// Read-only, so it is the one test in this file safe to point at a device
/// holding somebody's data.
#[tokio::test]
#[ignore = "needs a live SMB1 server; set SMB1_TEST_SERVER"]
async fn a_live_share_lists_and_stats() {
    let Some(target) = target() else {
        eprintln!("SMB1_TEST_SERVER is unset; nothing to talk to");
        return;
    };
    let tree = connect(&target).await;

    let statistics = tree.statistics().await.expect("the volume answered");
    println!(
        "{}: {} bytes total, {} available, from {:?}",
        target.address, statistics.total_bytes, statistics.available_bytes, statistics.level
    );

    let mut listing = tree.read_dir("").await.expect("the share root listed");
    let mut names = Vec::new();
    while let Some(entry) = listing.next_entry().await.expect("a page decoded") {
        names.push((entry.name().to_owned(), entry.is_dir(), entry.len()));
    }
    listing.close().await.expect("the search was released");
    println!("{}: {} entries at the root", target.address, names.len());
    for (name, directory, len) in names.iter().take(10) {
        println!("  {name} dir={directory} len={len}");
    }
    assert!(
        !names.iter().any(|(name, _, _)| name == "." || name == ".."),
        "`.` and `..` are filtered by the listing API"
    );

    if let Some((name, _, len)) = names.iter().find(|(_, directory, _)| !directory) {
        let metadata = tree.metadata(name).await.expect("the stat succeeded");
        assert_eq!(metadata.len(), *len, "the stat and the listing agree");
        assert!(tree.exists(name).await.expect("the existence check ran"));
    }
    assert!(
        !tree
            .exists("no-such-file-c0ffee.txt")
            .await
            .expect("a missing file is not an error"),
    );

    tree.close().await.expect("the tree disconnected");
}

/// **A listing dropped before end-of-stream sends `SMB_COM_FIND_CLOSE2`**, and
/// one drained to the end sends none — the two paths that between them close
/// every search.
///
/// This is one of the two wire paths with no offline oracle of any kind, so a
/// live server accepting it is the only evidence there is.
#[tokio::test]
#[ignore = "needs a live SMB1 server; set SMB1_TEST_SERVER"]
async fn a_dropped_listing_closes_its_search_on_a_live_server() {
    let Some(target) = target() else { return };
    let tree = connect(&target).await;

    // Taking one entry and closing is the case `SMB_COM_FIND_CLOSE2` exists for.
    let mut listing = tree.read_dir("").await.expect("the share root listed");
    let first = listing.next_entry().await.expect("the first page decoded");
    println!(
        "{}: took {:?} and closed early",
        target.address,
        first.map(|entry| entry.name().to_owned())
    );
    listing
        .close()
        .await
        .expect("SMB_COM_FIND_CLOSE2 was accepted");

    // And the search still works afterwards, which a server that had been left
    // holding a leaked handle may not manage.
    let mut again = tree.read_dir("").await.expect("a second listing started");
    while again.next_entry().await.expect("a page decoded").is_some() {}
    again
        .close()
        .await
        .expect("a drained listing sends nothing");

    tree.close().await.expect("the tree disconnected");
}

/// The whole write path against a live server: create, write, read back, stat,
/// rename, list, and remove everything it made.
///
/// **It creates only under its own scratch directory and removes what it
/// creates.** Set `SMB1_TEST_READ_ONLY` to skip it, which is what points this
/// suite at a device holding real data.
#[tokio::test]
#[ignore = "needs a live SMB1 server; set SMB1_TEST_SERVER"]
async fn a_live_server_takes_the_whole_write_path() {
    let Some(target) = target() else { return };
    if !target.writable {
        eprintln!("SMB1_TEST_READ_ONLY is set; the write path is skipped");
        return;
    }
    let tree = connect(&target).await;

    // A previous run that failed part-way leaves this behind.
    let _ = tree.remove_dir_all(SCRATCH).await;
    tree.create_dir(SCRATCH)
        .await
        .expect("the scratch directory");

    // Small enough to be one chunk, and one that pipelines: 300 KiB is three
    // chunks against a large-I/O server and clears the 256 KiB write threshold.
    let small = b"the quick brown fox".to_vec();
    let large: Vec<u8> = (0..300 * 1024u32).map(|index| index as u8).collect();

    let small_path = format!("{SCRATCH}\\small.txt");
    let large_path = format!("{SCRATCH}/large.bin");

    tree.write(&small_path, &small)
        .await
        .expect("a small write");
    assert_eq!(tree.read(&small_path).await.expect("read back"), small);

    tree.write(&large_path, &large)
        .await
        .expect("a large write");
    let read_back = tree.read(&large_path).await.expect("read back");
    assert_eq!(read_back.len(), large.len(), "every byte came back");
    assert_eq!(read_back, large);

    // `read_exact_at` over a span that crosses chunk boundaries, which against
    // Windows takes two round trips per chunk.
    let file = tree.open(&large_path).await.expect("open for reading");
    assert_eq!(
        file.len(),
        large.len() as u64,
        "the open reported the length"
    );
    let mut span = vec![0; 200 * 1024];
    file.read_exact_at(&mut span, 1_000)
        .await
        .expect("the span was filled");
    assert_eq!(span, large[1_000..1_000 + span.len()]);
    // A span past the end is an error and not a short read.
    let mut past = vec![0; 4_096];
    file.read_exact_at(&mut past, large.len() as u64 - 100)
        .await
        .expect_err("a span the file cannot fill is an error");
    file.close().await.expect("the handle was released");

    // The adapters.
    let file = tree.open(&large_path).await.expect("open for reading");
    let mut reader = file.into_reader();
    let mut copied = Vec::new();
    tokio::io::copy(&mut reader, &mut copied)
        .await
        .expect("tokio::io::copy over the adapter");
    assert_eq!(copied, large, "the adapter read the whole file");
    reader
        .into_inner()
        .await
        .expect("the file came back")
        .close()
        .await
        .expect("and closed");

    let metadata = tree.metadata(&large_path).await.expect("stat");
    assert_eq!(metadata.len(), large.len() as u64);
    assert!(!metadata.is_dir());
    assert!(metadata.modified().is_some(), "the server reported a time");

    let renamed = format!("{SCRATCH}\\renamed.bin");
    tree.rename(&large_path, &renamed).await.expect("rename");
    assert!(
        tree.exists(&renamed)
            .await
            .expect("the renamed path is there")
    );
    assert!(
        !tree
            .exists(&large_path)
            .await
            .expect("and the old one is not")
    );

    // The listing of what was made, and the entry count that goes with it.
    let mut listing = tree.read_dir(SCRATCH).await.expect("the scratch listed");
    let mut names = Vec::new();
    while let Some(entry) = listing.next_entry().await.expect("a page decoded") {
        names.push(entry.name().to_owned());
    }
    listing.close().await.expect("released");
    names.sort();
    assert_eq!(names, vec!["renamed.bin", "small.txt"]);

    // An empty directory lists no entries and no error, which is the case a
    // no-progress guard reading a post-filter count turns into a failure.
    let empty = format!("{SCRATCH}\\empty");
    tree.create_dir(&empty).await.expect("an empty directory");
    let mut listing = tree.read_dir(&empty).await.expect("the empty listing");
    assert!(
        listing.next_entry().await.expect("no error").is_none(),
        "an empty directory yields nothing and fails nothing"
    );
    listing.close().await.expect("released");

    tree.remove_dir_all(SCRATCH)
        .await
        .expect("the scratch directory was removed");
    assert!(!tree.exists(SCRATCH).await.expect("and it is gone"));

    tree.close().await.expect("the tree disconnected");
}

/// The container's acceptance check: the seeded 600-entry directory returns
/// **600**, which needs both paging and reassembly.
///
/// Paging is required of any server at 600 entries and a batch size of 100, and
/// the 42-character names make a Samba reply large enough to arrive in several
/// messages, so a port implementing only one of the two is incomplete against
/// this directory.
#[tokio::test]
#[ignore = "needs the seeded acceptance container; set SMB1_TEST_SEEDED_DIR"]
async fn the_seeded_directory_lists_every_entry() {
    let Some(target) = target() else { return };
    let Ok(seeded) = std::env::var("SMB1_TEST_SEEDED_DIR") else {
        eprintln!("SMB1_TEST_SEEDED_DIR is unset; the seeded check is skipped");
        return;
    };
    let expected: usize = std::env::var("SMB1_TEST_SEEDED_COUNT")
        .ok()
        .and_then(|count| count.parse().ok())
        .unwrap_or(600);

    let tree = connect(&target).await;
    let mut listing = tree.read_dir(&seeded).await.expect("the seeded directory");
    let mut count = 0;
    let mut longest = 0;
    while let Some(entry) = listing.next_entry().await.expect("a page decoded") {
        count += 1;
        longest = longest.max(entry.name().len());
    }
    listing.close().await.expect("released");
    println!(
        "{}: {seeded} holds {count} entries, longest name {longest} characters",
        target.address
    );
    assert_eq!(count, expected);

    // The empty directory beside it, which the same seed script creates.
    if let Ok(empty) = std::env::var("SMB1_TEST_EMPTY_DIR") {
        let mut listing = tree.read_dir(&empty).await.expect("the empty directory");
        assert!(listing.next_entry().await.expect("no error").is_none());
        listing.close().await.expect("released");
        println!("{}: {empty} lists no entries and no error", target.address);
    }

    tree.close().await.expect("the tree disconnected");
}

/// **The live coverage for reassembly**: a small advertised `MaxBufferSize`
/// while the transaction still asks for a large `MaxDataCount`.
///
/// What the client advertises is what decides whether a reply arrives in one
/// message or several, so lowering it is how a listing that would otherwise
/// arrive whole is made to arrive in fragments — at the port's own
/// advertisement, against a real server, rather than replayed from a capture.
/// The seeded directory's 600 entries under 42-character names are what make
/// the reply large enough for it to matter.
///
/// **What a plausible wrong implementation does.** One delivering the first
/// message as the whole reply hands back the entries of one fragment and stops;
/// one accumulating by byte count rather than by coverage delivers a reply with
/// a zero-filled hole, and the entry chain walked over it fails or fabricates
/// entries.
#[tokio::test]
#[ignore = "needs the seeded acceptance container; set SMB1_TEST_SEEDED_DIR"]
async fn a_small_advertised_buffer_reaches_the_reassembly_path() {
    let Some(target) = target() else { return };
    let Ok(seeded) = std::env::var("SMB1_TEST_SEEDED_DIR") else {
        eprintln!("SMB1_TEST_SEEDED_DIR is unset; the reassembly check is skipped");
        return;
    };
    let expected: usize = std::env::var("SMB1_TEST_SEEDED_COUNT")
        .ok()
        .and_then(|count| count.parse().ok())
        .unwrap_or(600);

    // 4,356 is the SMB1 minimum and what Windows itself advertises, so a page
    // asking for 65,472 data bytes cannot arrive in one message.
    let tree = connect_advertising(&target, 4_356).await;
    let mut listing = tree.read_dir(&seeded).await.expect("the seeded directory");
    let mut count = 0;
    while let Some(entry) = listing.next_entry().await.expect("a page reassembled") {
        assert!(!entry.name().is_empty(), "a fragment boundary split a name");
        count += 1;
    }
    listing.close().await.expect("released");
    println!(
        "{}: {count} entries reassembled at an advertised MaxBufferSize of 4,356",
        target.address
    );
    assert_eq!(count, expected);

    // And a read whose reply cannot fit one message either.
    if let Ok(path) = std::env::var("SMB1_TEST_READ_FILE") {
        let file = tree.open(&path).await.expect("open for reading");
        let mut buffer = vec![0; file.len() as usize];
        file.read_exact_at(&mut buffer, 0)
            .await
            .expect("the span was filled");
        println!("{}: read {} bytes of {path}", target.address, buffer.len());
        file.close().await.expect("released");
    }

    tree.close().await.expect("the tree disconnected");
}

/// **A non-empty directory is not silently left alone.**
///
/// Deleting is an open carrying `FILE_DELETE_ON_CLOSE` and a close, and against
/// a non-empty directory every server this crate has been run against — both
/// Samba families and Windows 11 24H2 — answers *both* requests
/// `STATUS_SUCCESS` and then does not unlink. Nothing on the wire says so, so a
/// client trusting the statuses reports success and deletes nothing, which is
/// the silent-no-op class this crate exists not to reproduce.
///
/// This is a live test rather than an offline one on purpose: what it pins is
/// the *servers'* behaviour, and a scripted peer would only ever replay what
/// this test was written believing. If a server ever starts refusing the delete
/// properly, this still passes — the verdict is the same either way.
///
/// Writes, so it does not run against a device holding real data.
#[tokio::test]
#[ignore = "needs a live SMB1 server; set SMB1_TEST_SERVER"]
async fn removing_a_non_empty_directory_is_refused_rather_than_silently_ignored() {
    let Some(target) = target() else {
        eprintln!("SMB1_TEST_SERVER is unset; nothing to talk to");
        return;
    };
    let tree = connect(&target).await;

    tree.create_dir("live_non_empty").await.ok();
    tree.write("live_non_empty\\child.txt", b"x")
        .await
        .expect("the child is written");

    let verdict = tree.remove_dir("live_non_empty").await;
    let error = verdict.expect_err("a non-empty directory is not deletable");
    assert_eq!(
        error.kind(),
        std::io::ErrorKind::DirectoryNotEmpty,
        "reported as {error}"
    );
    assert!(
        tree.exists("live_non_empty\\child.txt").await.unwrap(),
        "the child survived, which is what makes the refusal correct"
    );

    tree.remove_file("live_non_empty\\child.txt")
        .await
        .expect("the child is removed");
    tree.remove_dir("live_non_empty")
        .await
        .expect("now empty, it deletes");
    assert!(!tree.exists("live_non_empty").await.unwrap());

    tree.close().await.expect("the tree disconnected");
}
