//! The filesystem layer over the connection's test seam: the read fill loop,
//! the listing's two terminators and both ways it closes its search, the chunk
//! size's three cases, and the verbs' wire shapes.
//!
//! Everything here is offline and deterministic. What it can express that no
//! capture can is a server answering *badly*: a chunk served short, a chunk
//! served nothing, a page that neither carries entries nor ends.

mod harness;

use std::time::Duration;

use tokio::io::AsyncReadExt;
use tokio::time::timeout;

use smb1client::connection::Timeouts;
use smb1client::{Error, File, NtStatus, Tree};

use harness::{
    CLOSE, FIND_CLOSE2, NT_CREATE_ANDX, Peer, READ_ANDX, TRANSACTION2, bodyless, chain, command_of,
    create_request, find_first_parameters, find_next_parameters, large_io, mid_of, read_request,
    read_response, small_io, trans2_parameters, trans2_subcommand, transaction_response, tree,
};

/// The chunk a large-I/O server buys.
const CHUNK: usize = 130_048;

/// What Windows 11 24H2 serves on every `READ_ANDX`, whatever was asked.
const WINDOWS_READ_CAP: usize = 65_536;

const FIND_FIRST2: u16 = 0x0001;
const FIND_NEXT2: u16 = 0x0002;
const QUERY_PATH_INFORMATION: u16 = 0x0005;
const SET_PATH_INFORMATION: u16 = 0x0006;
const QUERY_FS_INFORMATION: u16 = 0x0003;

async fn open(tree: &Tree, peer: &mut Peer, len: u64) -> File {
    let tree = tree.clone();
    let opening = tokio::spawn(async move { tree.open("a.txt").await });
    peer.answer_open(0x10, len).await;
    opening.await.unwrap().expect("the open succeeded")
}

// ===========================================================================
// The read fill loop.
// ===========================================================================

/// **A chunk answered short is re-issued for the bytes it did not return.**
///
/// This is not defensive. Windows 11 24H2 serves every `READ_ANDX`
/// `min(asked, 65536)` while accepting a 130,048-byte write, so against that
/// server this path runs on *every* large read: a 130,048-byte chunk takes two
/// round trips rather than one.
///
/// **What a plausible wrong implementation does.** One that reads a short answer
/// as end of file returns 65,536 of 130,048 bytes and loses the rest of the file
/// silently — which is exactly what the reference library does.
#[tokio::test(start_paused = true)]
async fn a_short_chunk_is_re_issued_rather_than_read_as_end_of_file() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let file = open(&tree, &mut peer, CHUNK as u64).await;

    let reading = tokio::spawn(async move {
        let mut buffer = vec![0; CHUNK];
        file.read_exact_at(&mut buffer, 0).await.map(|()| buffer)
    });

    // The whole chunk is asked for, and Windows' cap is served.
    let first = peer.frame().await;
    assert_eq!(read_request(&first), (0, CHUNK as u32));
    peer.send(&read_response(
        mid_of(&first),
        &vec![0xA1; WINDOWS_READ_CAP],
    ))
    .await;

    // The remainder is re-issued from where the short answer stopped.
    let second = peer.frame().await;
    assert_eq!(
        read_request(&second),
        (WINDOWS_READ_CAP as u64, (CHUNK - WINDOWS_READ_CAP) as u32),
        "the re-issue asks for the bytes the first answer did not return"
    );
    peer.send(&read_response(
        mid_of(&second),
        &vec![0xA2; CHUNK - WINDOWS_READ_CAP],
    ))
    .await;

    let filled = reading.await.unwrap().expect("the span was filled");
    assert_eq!(filled.len(), CHUNK);
    assert_eq!(filled[..WINDOWS_READ_CAP], vec![0xA1; WINDOWS_READ_CAP]);
    assert_eq!(
        filled[WINDOWS_READ_CAP..],
        vec![0xA2; CHUNK - WINDOWS_READ_CAP]
    );
}

/// **A chunk answered with zero bytes is never re-issued**, and the span it
/// leaves uncovered fails the call.
///
/// That is the loop's no-progress guard, and it reads off the covered ranges
/// rather than off the cached size — which nothing may gate a read on.
///
/// **What a plausible wrong implementation does.** One that re-issues a
/// zero-byte answer the way it re-issues a short one asks the same question for
/// ever. One that gates the read on the cached length short-circuits and returns
/// `Ok` with a zeroed buffer, which is smb-rs's own defect.
#[tokio::test(start_paused = true)]
async fn a_chunk_answered_with_zero_bytes_is_never_re_issued() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let file = open(&tree, &mut peer, 4_096).await;

    let reading = tokio::spawn(async move {
        let mut buffer = vec![0; 4_096];
        file.read_exact_at(&mut buffer, 0).await
    });

    let first = peer.frame().await;
    assert_eq!(read_request(&first), (0, 4_096));
    peer.send(&read_response(mid_of(&first), &[])).await;

    let error = reading
        .await
        .unwrap()
        .expect_err("the span could not be filled");
    // Ordinary end of file, not a server sending nonsense: `std`'s `read_exact`
    // answers `UnexpectedEof` when it runs out, and this method carries `std`'s
    // contract along with its name.
    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
    assert!(
        error.to_string().contains("4096 bytes at offset 0"),
        "the error names the uncovered range: {error}"
    );

    let rest = peer.drain().await;
    assert!(
        rest.iter().all(|frame| command_of(frame) != READ_ANDX),
        "the zero-byte answer was not re-issued"
    );
}

/// **A hole in the middle fails the call as surely as a short far end**, and
/// only the error's text distinguishes them.
///
/// The middle chunk answers nothing while the chunk after it answers in full, so
/// a loop tracking a running total sees 260,096 of 262,144 bytes and a coverage
/// map sees a 130,048-byte hole at 130,048.
///
/// **What a plausible wrong implementation does.** One counting bytes returns
/// `Ok` with a zero-filled hole in the middle of the caller's buffer — silent
/// corruption, arriving through the check meant to prevent it.
#[tokio::test(start_paused = true)]
async fn a_hole_in_the_middle_fails_the_call() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let span = 2 * CHUNK + 2_048;
    let file = open(&tree, &mut peer, span as u64).await;

    let reading = tokio::spawn(async move {
        let mut buffer = vec![0; span];
        file.read_exact_at(&mut buffer, 0).await
    });

    let frames = peer.drain().await;
    assert_eq!(
        frames.len(),
        3,
        "the read pipelines over the 128 KiB threshold"
    );
    peer.send(&read_response(mid_of(&frames[0]), &vec![0xB1; CHUNK]))
        .await;
    // The middle chunk answers nothing, which ends it without re-issue.
    peer.send(&read_response(mid_of(&frames[1]), &[])).await;
    peer.send(&read_response(mid_of(&frames[2]), &vec![0xB3; 2_048]))
        .await;

    let error = reading.await.unwrap().expect_err("the span has a hole");
    assert!(
        error
            .to_string()
            .contains(&format!("{CHUNK} bytes at offset {CHUNK}")),
        "the error names the hole: {error}"
    );
    // A hole is an unfilled span, not a server that sent nonsense: `std` answers
    // `UnexpectedEof` for a `read_exact` that ran out and this method carries
    // `std`'s contract along with its name.
    assert_eq!(error.kind(), std::io::ErrorKind::UnexpectedEof);
}

/// **`STATUS_END_OF_FILE` is a zero-byte answer under a status rather than a
/// count**: not an error, not re-issued, and it returns the bytes already
/// covered.
///
/// `Tree::read` is the one place the fill-or-error rule does not apply — it
/// sizes its buffer from the length the open reported, so a file another writer
/// truncated in between answers short at the far end, and what comes back is
/// what was there.
#[tokio::test(start_paused = true)]
async fn status_end_of_file_ends_a_whole_file_read_rather_than_failing_it() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let reading = {
        let tree = tree.clone();
        tokio::spawn(async move { tree.read("a.txt").await })
    };

    // The open says 4,096 bytes; the file has since been truncated to 1,000.
    peer.answer_open(0x10, 4_096).await;
    let first = peer.frame().await;
    assert_eq!(read_request(&first), (0, 4_096));
    peer.send(&read_response(mid_of(&first), &vec![0xC7; 1_000]))
        .await;
    let second = peer.frame().await;
    assert_eq!(read_request(&second), (1_000, 3_096));
    peer.send(&bodyless(READ_ANDX, NtStatus::END_OF_FILE, mid_of(&second)))
        .await;
    peer.answer_close().await;

    let bytes = reading.await.unwrap().expect("end of file is not an error");
    assert_eq!(bytes, vec![0xC7; 1_000]);
}

/// **The chunk size has three cases**, and the one-shot downgrade is the third.
///
/// A server refusing a large read with one of the three statuses that mean it
/// has that operation retried once at `MaxBufferSize − 1024`, and is recorded
/// small-buffer for the life of the connection — so every later chunk on it is
/// bounded the same way and nothing is attempted a third time.
///
/// **What a plausible wrong implementation does.** One triggering on any error
/// spends a connection's throughput on an unrelated failure. One retrying per
/// chunk rather than recording the downgrade once pays the refusal on every
/// chunk for the rest of the connection's life.
#[tokio::test(start_paused = true)]
async fn a_refused_chunk_downgrades_the_connection_once_and_retries_it() {
    let negotiated = large_io();
    let (tree, mut peer) = tree(negotiated, Timeouts::default());
    let downgraded = (negotiated.max_buffer_size - 1_024) as usize;
    let file = open(&tree, &mut peer, CHUNK as u64).await;

    // The span must be **larger** than the downgraded chunk, or the first
    // request is already small and the test cannot tell a retry that re-clamps
    // from one that re-sends the size the server just refused. An earlier
    // version read exactly `downgraded` bytes and proved nothing.
    let reading = tokio::spawn(async move {
        let mut buffer = vec![0; CHUNK];
        file.read_exact_at(&mut buffer, 0).await?;
        let mut again = vec![0; downgraded];
        file.read_exact_at(&mut again, 0).await
    });

    let first = peer.frame().await;
    assert_eq!(
        read_request(&first).1,
        CHUNK as u32,
        "the first ask is the large chunk the capabilities allow"
    );
    peer.send(&bodyless(
        READ_ANDX,
        NtStatus::INVALID_PARAMETER,
        mid_of(&first),
    ))
    .await;

    // The same operation, retried once, and re-clamped: asking again at the
    // refused size would fail for the reason the first attempt did.
    let retry = peer.frame().await;
    assert_eq!(
        read_request(&retry).1,
        downgraded as u32,
        "the retry asks at MaxBufferSize - 1024, not at the refused size"
    );
    peer.send(&read_response(mid_of(&retry), &vec![0xD4; downgraded]))
        .await;

    // The rest of that same span, in as many rounds as the downgraded size
    // takes. What is asserted is the property rather than the arithmetic: no
    // request after the downgrade exceeds it, which is the whole point of it.
    let mut covered = downgraded;
    while covered < CHUNK {
        let more = peer.frame().await;
        let (_, length) = read_request(&more);
        assert!(
            length as usize <= downgraded,
            "a request after the downgrade asked for {length}, above the {downgraded} it is bounded by"
        );
        peer.send(&read_response(mid_of(&more), &vec![0xD4; length as usize]))
            .await;
        covered += length as usize;
    }

    // The next read is bounded the same way without asking again.
    let later = peer.frame().await;
    assert_eq!(
        read_request(&later).1,
        downgraded as u32,
        "the connection stays small-buffer"
    );
    peer.send(&read_response(mid_of(&later), &vec![0xD5; downgraded]))
        .await;

    reading.await.unwrap().expect("both reads completed");
}

/// **A server without the large-I/O capabilities is bounded by the field that
/// asks for the bytes, under the reservation** — `min(65,520, MaxBufferSize −
/// 1024)` — and not by the negotiated buffer alone.
#[tokio::test(start_paused = true)]
async fn a_server_without_the_capability_asks_for_the_smaller_bound() {
    let (tree, mut peer) = tree(small_io(16_644), Timeouts::default());
    let file = open(&tree, &mut peer, 200_000).await;
    let reading = tokio::spawn(async move {
        let mut buffer = vec![0; 200_000];
        file.read_exact_at(&mut buffer, 0).await
    });

    let first = peer.frame().await;
    assert_eq!(read_request(&first).1, 16_644 - 1_024);
    drop(reading);
    let _ = peer.drain().await;
}

/// The reader adapter reports end of file the way `AsyncRead` does everywhere,
/// and it reads that end **off the wire** rather than off a count.
#[tokio::test(start_paused = true)]
async fn the_reader_adapter_reports_end_of_file_off_the_wire() {
    let (tree, mut peer) = tree(small_io(8_192), Timeouts::default());
    // One chunk per fill, so the frames below are the whole of what the adapter
    // asks: at the default read-ahead of four it would issue four at once.
    tree.set_read_ahead(1);
    let file = open(&tree, &mut peer, 0).await;
    let reading = tokio::spawn(async move {
        let mut reader = file.into_reader();
        let mut out = Vec::new();
        reader.read_to_end(&mut out).await.map(|_| out)
    });

    // The open reported a length of zero, and the file has bytes anyway: the
    // adapter never gates a read on the cached size.
    let first = peer.frame().await;
    peer.send(&read_response(mid_of(&first), &vec![0xE1; 1_234]))
        .await;
    let second = peer.frame().await;
    assert_eq!(read_request(&second).0, 1_234);
    peer.send(&read_response(mid_of(&second), &[])).await;

    let bytes = reading.await.unwrap().expect("the adapter read to the end");
    assert_eq!(bytes, vec![0xE1; 1_234]);
}

// ===========================================================================
// The listing.
// ===========================================================================

/// A FIND reply carrying `names`, with the parameter block of whichever request
/// it answers.
fn find_reply(mid: u16, first: bool, names: &[(&str, bool)], end_of_search: bool) -> Vec<u8> {
    let data = chain(names);
    let parameters = if first {
        find_first_parameters(0x0100, names.len() as u16, end_of_search)
    } else {
        find_next_parameters(names.len() as u16, end_of_search)
    };
    transaction_response(mid, NtStatus::SUCCESS, &parameters, &data)
}

/// **Both terminators end a listing**, and `.` and `..` are filtered above the
/// parser.
#[tokio::test(start_paused = true)]
async fn a_listing_ends_on_end_of_search() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let listing = {
        let tree = tree.clone();
        tokio::spawn(async move {
            let mut listing = tree.read_dir("dir").await?;
            let mut names = Vec::new();
            while let Some(entry) = listing.next_entry().await? {
                names.push(entry.name().to_owned());
            }
            listing.close().await?;
            Ok::<_, Error>(names)
        })
    };

    let first = peer.frame().await;
    assert_eq!(trans2_subcommand(&first), FIND_FIRST2);
    peer.send(&find_reply(
        mid_of(&first),
        true,
        &[(".", true), ("..", true), ("alpha.txt", false)],
        true,
    ))
    .await;

    assert_eq!(listing.await.unwrap().unwrap(), vec!["alpha.txt"]);
    assert!(
        peer.drain().await.is_empty(),
        "a drained listing has already been closed by the server"
    );
}

/// The second terminator: a FIND answered `STATUS_NO_MORE_FILES`, which carries
/// no entries and is not an error.
#[tokio::test(start_paused = true)]
async fn a_listing_ends_on_status_no_more_files() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let listing = {
        let tree = tree.clone();
        tokio::spawn(async move {
            let mut listing = tree.read_dir("dir").await?;
            let mut names = Vec::new();
            while let Some(entry) = listing.next_entry().await? {
                names.push(entry.name().to_owned());
            }
            Ok::<_, Error>(names)
        })
    };

    let first = peer.frame().await;
    peer.send(&find_reply(
        mid_of(&first),
        true,
        &[("alpha.txt", false)],
        false,
    ))
    .await;

    let next = peer.frame().await;
    assert_eq!(trans2_subcommand(&next), FIND_NEXT2);
    peer.send(&bodyless(
        TRANSACTION2,
        NtStatus::NO_MORE_FILES,
        mid_of(&next),
    ))
    .await;

    assert_eq!(listing.await.unwrap().unwrap(), vec!["alpha.txt"]);
}

/// **The no-progress guard counts the entries the server returned, before `.`
/// and `..` are removed.**
///
/// An empty directory's first page is `.` and `..` and nothing else. On a server
/// that does not set `EndOfSearch` on it — which is the ordinary case the
/// container itself produces — a guard reading the post-filter count turns
/// listing an empty directory into an error.
///
/// **What a plausible wrong implementation does.** Counting after the filter
/// fails every listing of an empty directory. Dropping the guard altogether
/// pages for ever against a server answering `SearchCount = 0` with
/// `EndOfSearch = 0`.
#[tokio::test(start_paused = true)]
async fn an_empty_directory_lists_no_entries_and_no_error() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let listing = {
        let tree = tree.clone();
        tokio::spawn(async move {
            let mut listing = tree.read_dir("empty").await?;
            let mut names = Vec::new();
            while let Some(entry) = listing.next_entry().await? {
                names.push(entry.name().to_owned());
            }
            Ok::<_, Error>(names)
        })
    };

    let first = peer.frame().await;
    peer.send(&find_reply(
        mid_of(&first),
        true,
        &[(".", true), ("..", true)],
        false,
    ))
    .await;
    let next = peer.frame().await;
    peer.send(&bodyless(
        TRANSACTION2,
        NtStatus::NO_MORE_FILES,
        mid_of(&next),
    ))
    .await;

    let names = listing
        .await
        .unwrap()
        .expect("an empty directory is not an error");
    assert!(names.is_empty());
}

/// A page that yields no entries and neither terminator is an error rather than
/// another round.
#[tokio::test(start_paused = true)]
async fn a_page_that_returns_nothing_and_does_not_end_fails() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let listing = {
        let tree = tree.clone();
        tokio::spawn(async move { tree.read_dir("dir").await.map(|_| ()) })
    };

    let first = peer.frame().await;
    peer.send(&find_reply(mid_of(&first), true, &[], false))
        .await;

    let error = listing
        .await
        .unwrap()
        .expect_err("the page made no progress");
    assert!(
        error.to_string().contains("did not end"),
        "the error says what happened: {error}"
    );
}

/// **`SMB_FIND_CLOSE_AT_EOS` goes on the FIND_FIRST2 and on every FIND_NEXT2**,
/// so whichever request reaches end-of-stream is the one that asks the server to
/// close the search.
///
/// **What a plausible wrong implementation does.** The reference sets it on the
/// FIND_FIRST2 alone and sends `SMB_FIND_CONTINUE_FROM_LAST` on every
/// FIND_NEXT2, so every listing longer than one page ends on a request that
/// never asked the server to close — the leak behind its recursive delete's
/// retry loop.
#[tokio::test(start_paused = true)]
async fn every_find_next2_asks_the_server_to_close_at_end_of_stream() {
    const CLOSE_AT_EOS: u16 = 0x0002;
    const CONTINUE_FROM_LAST: u16 = 0x0008;

    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let listing = {
        let tree = tree.clone();
        tokio::spawn(async move {
            let mut listing = tree.read_dir("dir").await?;
            while listing.next_entry().await?.is_some() {}
            Ok::<_, Error>(())
        })
    };

    let first = peer.frame().await;
    let flags = u16::from_le_bytes([trans2_parameters(&first)[4], trans2_parameters(&first)[5]]);
    assert_eq!(flags & CLOSE_AT_EOS, CLOSE_AT_EOS, "on the FIND_FIRST2");
    peer.send(&find_reply(mid_of(&first), true, &[("a", false)], false))
        .await;

    let next = peer.frame().await;
    let parameters = trans2_parameters(&next);
    let flags = u16::from_le_bytes([parameters[10], parameters[11]]);
    assert_eq!(
        flags,
        CLOSE_AT_EOS | CONTINUE_FROM_LAST,
        "and on the FIND_NEXT2, beside the continuation flag"
    );
    // It also repeats the search id and the pattern: a FIND_NEXT2 is not
    // self-contained.
    assert_eq!(u16::from_le_bytes([parameters[0], parameters[1]]), 0x0100);
    peer.send(&find_reply(mid_of(&next), false, &[("b", false)], true))
        .await;

    listing.await.unwrap().unwrap();
}

/// **A listing dropped before end-of-stream sends `SMB_COM_FIND_CLOSE2`**, which
/// lazy listing makes ordinary — taking the first ten entries and dropping the
/// iterator would otherwise leave the search open.
#[tokio::test(start_paused = true)]
async fn a_listing_dropped_before_the_end_closes_its_search() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let listing = {
        let tree = tree.clone();
        tokio::spawn(async move {
            let mut listing = tree.read_dir("dir").await?;
            let first = listing.next_entry().await?;
            // The iterator is dropped here, with the search still open.
            drop(listing);
            Ok::<_, Error>(first.map(|entry| entry.name().to_owned()))
        })
    };

    let first = peer.frame().await;
    peer.send(&find_reply(
        mid_of(&first),
        true,
        &[("a", false), ("b", false)],
        false,
    ))
    .await;

    assert_eq!(listing.await.unwrap().unwrap().as_deref(), Some("a"));
    let closes = peer.drain().await;
    assert_eq!(
        closes
            .iter()
            .map(|frame| command_of(frame))
            .collect::<Vec<_>>(),
        vec![FIND_CLOSE2],
        "the dropped listing released the search"
    );
    assert_eq!(
        u16::from_le_bytes([closes[0][33], closes[0][34]]),
        0x0100,
        "and it named the search the FIND_FIRST2 reply returned"
    );
}

// ===========================================================================
// The verbs.
// ===========================================================================

/// **Deleting is an open and a close**, and the create option is what says which
/// kind of object the open expects — so a `remove_file` aimed at a directory is
/// refused by the server rather than by a client-side check that spends a round
/// trip to reach the same refusal.
#[tokio::test(start_paused = true)]
async fn deleting_is_an_open_under_delete_on_close_and_then_a_close() {
    const DELETE: u32 = 0x0001_0000;
    const FILE_OPEN: u32 = 1;
    const FILE_DIRECTORY_FILE: u32 = 0x0000_0001;
    const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
    const FILE_DELETE_ON_CLOSE: u32 = 0x0000_1000;

    for (directory, expected) in [
        (false, FILE_NON_DIRECTORY_FILE),
        (true, FILE_DIRECTORY_FILE),
    ] {
        let (tree, mut peer) = tree(large_io(), Timeouts::default());
        let removing = {
            let tree = tree.clone();
            tokio::spawn(async move {
                if directory {
                    tree.remove_dir("dir").await
                } else {
                    tree.remove_file("a.txt").await
                }
            })
        };

        let opened = peer.answer_open(0x22, 0).await;
        let (access, disposition, options) = create_request(&opened);
        assert_eq!(access, DELETE, "the open asks for DELETE and nothing else");
        assert_eq!(disposition, FILE_OPEN);
        assert_eq!(options, expected | FILE_DELETE_ON_CLOSE);

        let closed = peer.answer_close().await;
        // `LastWriteTime = 0` tells the server to leave the time it has alone.
        assert_eq!(closed[35..39], [0, 0, 0, 0]);
        if directory {
            // A directory delete is checked afterwards: every tested server
            // answers a delete-on-close against a non-empty directory with
            // success and then does not unlink, so the statuses cannot say.
            peer.answer_gone().await;
        }
        removing.await.unwrap().expect("the delete succeeded");
    }
}

/// **`remove_dir_all` collects each level fully before deleting from it**, and
/// the level it drained is one the server has already closed — so awaiting that
/// close costs a round trip nobody makes.
#[tokio::test(start_paused = true)]
async fn remove_dir_all_drains_a_level_before_it_deletes_from_it() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let removing = {
        let tree = tree.clone();
        tokio::spawn(async move { tree.remove_dir_all("dir").await })
    };

    let first = peer.frame().await;
    assert_eq!(trans2_subcommand(&first), FIND_FIRST2);
    peer.send(&find_reply(
        mid_of(&first),
        true,
        &[(".", true), ("..", true), ("a.txt", false)],
        true,
    ))
    .await;

    // The child, then the directory itself: two opens and two closes, and no
    // FIND_CLOSE2 between them — then the query that confirms the directory
    // really went, which a delete-on-close cannot say for itself.
    let mut sent = Vec::new();
    for _ in 0..5 {
        let frame = peer
            .answer(|frame, mid| match command_of(frame) {
                NT_CREATE_ANDX => harness::create_response(mid, 0x30, 0, false),
                CLOSE => bodyless(CLOSE, NtStatus::SUCCESS, mid),
                TRANSACTION2 => bodyless(TRANSACTION2, NtStatus::OBJECT_NAME_NOT_FOUND, mid),
                other => panic!("unexpected command {other:#04x}"),
            })
            .await;
        sent.push(frame);
    }

    removing.await.unwrap().expect("the tree was removed");
    assert_eq!(
        sent.iter()
            .map(|frame| command_of(frame))
            .collect::<Vec<_>>(),
        vec![NT_CREATE_ANDX, CLOSE, NT_CREATE_ANDX, CLOSE, TRANSACTION2]
    );
    assert_eq!(harness::create_name(&sent[0]), "dir\\a.txt");
    assert_eq!(harness::create_name(&sent[2]), "dir");
    assert!(
        peer.drain()
            .await
            .iter()
            .all(|frame| command_of(frame) != FIND_CLOSE2),
        "the drained listing needed no FIND_CLOSE2"
    );
}

/// **A stat is two queries**, neither level carrying both halves.
#[tokio::test(start_paused = true)]
async fn a_stat_issues_the_two_levels_it_needs() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let stat = {
        let tree = tree.clone();
        tokio::spawn(async move { tree.metadata("dir/a.txt").await })
    };

    let basic = peer.frame().await;
    assert_eq!(trans2_subcommand(&basic), QUERY_PATH_INFORMATION);
    assert_eq!(trans2_parameters(&basic)[..2], 0x0101u16.to_le_bytes());
    let mut block = Vec::new();
    for _ in 0..4 {
        block.extend_from_slice(&0i64.to_le_bytes());
    }
    block.extend_from_slice(&0x10u32.to_le_bytes());
    peer.send(&transaction_response(
        mid_of(&basic),
        NtStatus::SUCCESS,
        &[],
        &block,
    ))
    .await;

    let standard = peer.frame().await;
    assert_eq!(trans2_parameters(&standard)[..2], 0x0102u16.to_le_bytes());
    let mut block = Vec::new();
    block.extend_from_slice(&4_096u64.to_le_bytes());
    block.extend_from_slice(&11u64.to_le_bytes());
    block.extend_from_slice(&1u32.to_le_bytes());
    block.push(0);
    block.push(1);
    peer.send(&transaction_response(
        mid_of(&standard),
        NtStatus::SUCCESS,
        &[],
        &block,
    ))
    .await;

    let metadata = stat.await.unwrap().expect("the stat succeeded");
    assert_eq!(metadata.len(), 11);
    assert_eq!(metadata.allocation_size(), 4_096);
    assert!(
        metadata.is_dir(),
        "the attributes say so, not a second query"
    );
}

/// **`set_attributes(0)` sends `FILE_ATTRIBUTE_NORMAL`**, which is what actually
/// clears them: a zero attribute word means "do not change" and would return
/// success having changed nothing.
#[tokio::test(start_paused = true)]
async fn clearing_every_attribute_sends_the_value_that_clears_them() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let setting = {
        let tree = tree.clone();
        tokio::spawn(async move { tree.set_attributes("a.txt", 0).await })
    };

    let frame = peer.frame().await;
    assert_eq!(trans2_subcommand(&frame), SET_PATH_INFORMATION);
    let data = harness::trans2_data(&frame);
    assert_eq!(data.len(), 40, "the level's whole block");
    assert_eq!(data[..32], [0; 32], "and the timestamps are left alone");
    assert_eq!(
        u32::from_le_bytes([data[32], data[33], data[34], data[35]]),
        0x80,
        "FILE_ATTRIBUTE_NORMAL, and not the zero that changes nothing"
    );
    peer.send(&transaction_response(
        mid_of(&frame),
        NtStatus::SUCCESS,
        &[],
        &[],
    ))
    .await;
    setting.await.unwrap().expect("the attributes were set");
}

/// **The volume fallback triggers on any error from the modern level**, and the
/// answer says which level produced it.
#[tokio::test(start_paused = true)]
async fn the_volume_query_falls_back_and_says_which_level_answered() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let asking = {
        let tree = tree.clone();
        tokio::spawn(async move { tree.statistics().await })
    };

    let modern = peer.frame().await;
    assert_eq!(trans2_subcommand(&modern), QUERY_FS_INFORMATION);
    assert_eq!(trans2_parameters(&modern), 0x0103u16.to_le_bytes());
    peer.send(&bodyless(
        TRANSACTION2,
        NtStatus::NOT_SUPPORTED,
        mid_of(&modern),
    ))
    .await;

    let legacy = peer.frame().await;
    assert_eq!(trans2_parameters(&legacy), 0x0001u16.to_le_bytes());
    let mut block = Vec::new();
    block.extend_from_slice(&0u32.to_le_bytes());
    block.extend_from_slice(&8u32.to_le_bytes());
    block.extend_from_slice(&1_000u32.to_le_bytes());
    block.extend_from_slice(&400u32.to_le_bytes());
    block.extend_from_slice(&512u16.to_le_bytes());
    peer.send(&transaction_response(
        mid_of(&legacy),
        NtStatus::SUCCESS,
        &[],
        &block,
    ))
    .await;

    let statistics = asking.await.unwrap().expect("the fallback answered");
    assert_eq!(statistics.total_bytes, 1_000 * 8 * 512);
    assert_eq!(statistics.available_bytes, 400 * 8 * 512);
    assert_eq!(statistics.level, smb1client::FsInfoLevel::Allocation);
}

/// **Both transaction limits are enforced where the request is built**, before
/// anything reaches the wire.
///
/// A long path is the realistic way the one-message rule breaks: SMB1's
/// secondary exchange is not implemented, so a request that would not fit fails
/// locally, naming the limit and the request that exceeded it. It is not
/// truncated and it is not silently split.
#[tokio::test(start_paused = true)]
async fn a_transaction_that_does_not_fit_one_message_fails_before_the_wire() {
    let (tree, mut peer) = tree(small_io(4_356), Timeouts::default());
    let path = "d".repeat(4_096);
    let error = tree
        .metadata(&path)
        .await
        .expect_err("the request does not fit one message");
    match error {
        Error::TransactionTooLarge {
            request,
            size,
            limit,
        } => {
            assert_eq!(request, "TRANS2_QUERY_PATH_INFORMATION");
            assert!(size > limit);
            assert_eq!(limit, 4_356);
        }
        other => panic!("expected a size refusal, got {other}"),
    }
    assert!(
        peer.next_frame().await.is_none(),
        "nothing reached the wire"
    );
}

/// A path the policy refuses never reaches the wire either.
#[tokio::test(start_paused = true)]
async fn a_path_that_escapes_the_share_is_refused_before_the_wire() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    for path in ["..\\..\\etc\\passwd", "\\absolute", "a\0b"] {
        let error = tree.metadata(path).await.expect_err("refused");
        assert!(matches!(error, Error::InvalidPath(_)), "{path}: {error}");
    }
    assert!(peer.next_frame().await.is_none());
}

/// A dropped file enqueues its close, and an awaited one reports the round
/// trip's failure.
#[tokio::test(start_paused = true)]
async fn a_dropped_file_enqueues_its_close() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let file = open(&tree, &mut peer, 0).await;
    drop(file);

    let frames = timeout(Duration::from_secs(1), peer.drain())
        .await
        .expect("the close was enqueued");
    assert_eq!(
        frames
            .iter()
            .map(|frame| command_of(frame))
            .collect::<Vec<_>>(),
        vec![CLOSE]
    );
}
