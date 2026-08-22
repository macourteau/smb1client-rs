//! **Invariant 4** — a cancelled write never reports more than the contiguous
//! prefix that reached the server.
//!
//! Two ways a write stops, and they differ in what can be reported at all. The
//! library's own per-request timeout fires on one of the write's requests, the
//! write future completes normally with an error, and that error can carry a
//! number. A caller that drops the future gets nothing that way ever — a dropped
//! future yields no value — so the number reaches it through a
//! [`WriteProgress`] it passed by value, which outlives the future and is read
//! afterwards.
//!
//! The handle carries a completion signal as well as the ranges, because without
//! one it is a structure nobody can safely read: `Drop` returns immediately, so
//! the handle is not final at the drop. The signal keys on the **chunk group**
//! and not on the connection's request table — a lapsed request leaves the group
//! at the lapse while it stays in the table holding its multiplex id — and
//! Orphaned has three exits, all three covered here: an arrival that ends the
//! request, whether by completing the reply or by corrupting it; the request
//! lapsing on a timeout; and the connection dying. A caller drop is the *entry*
//! to Orphaned, not an exit from it.
//!
//! Every test here drives the same fake transport the connection's own tests do,
//! with per-chunk acknowledgement under the test's control. `tests/COVERAGE.md`
//! records what each catches.

mod harness;

use std::time::Duration;

use tokio::time::timeout;

use smb1client::connection::Timeouts;
use smb1client::{Error, File, NtStatus, Tree, WriteProgress};

use harness::{
    Peer, WRITE_ANDX, command_of, large_io, mid_of, tree, write_request, write_response,
};

/// The chunk size a large-I/O server buys, which is what a write is cut into.
const CHUNK: usize = 130_048;

/// Three chunks: two whole ones and a 2 KiB tail. Over the 256 KiB threshold, so
/// the write pipelines and all three are on the wire at once — which is what
/// makes an out-of-order acknowledgement expressible at all.
const SPAN: usize = 2 * CHUNK + 2_048;

/// Opens a file over the seam.
async fn open(tree: &Tree, peer: &mut Peer) -> File {
    let tree = tree.clone();
    let opening = tokio::spawn(async move { tree.open("a.txt").await });
    peer.answer_open(0x10, 0).await;
    opening.await.unwrap().expect("the open succeeded")
}

/// The offset and length each `WRITE_ANDX` frame carried, in the order they
/// arrived.
fn offered(frames: &[Vec<u8>]) -> Vec<(u64, u32)> {
    frames
        .iter()
        .inspect(|frame| assert_eq!(command_of(frame), WRITE_ANDX))
        .map(|frame| write_request(frame))
        .collect()
}

/// **Invariant 4, the library's own timeout.** The error carries the contiguous
/// prefix, which is not the sum of what was acknowledged.
///
/// The first chunk and the *third* are acknowledged and the second is not, so a
/// running total says 132,096 bytes reached the server and the prefix says
/// 130,048. Only the prefix is safe to resume from: the bytes of the third chunk
/// are on the server, and a caller resuming at 132,096 would leave the second
/// chunk's 130,048 bytes as a hole it never writes.
///
/// **What a plausible wrong implementation does.** One that counts acknowledged
/// bytes reports 132,096. One that counts what each chunk *asked* to write
/// reports 262,144 and claims the whole write landed. One that returns the
/// moment the first error arrives — rather than draining what is already
/// outstanding — reports whatever had been acknowledged by then, which is a race
/// rather than a number.
#[tokio::test(start_paused = true)]
async fn invariant_4_a_timeout_reports_the_prefix_and_not_the_sum() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let file = open(&tree, &mut peer).await;
    let data = vec![0xAB; SPAN];

    let progress = WriteProgress::new();
    let writing = tokio::spawn({
        let progress = progress.clone();
        let file = file;
        async move {
            file.write_all_at(&vec![0xAB; SPAN], 0, Some(progress))
                .await
        }
    });

    let frames = peer.drain().await;
    assert_eq!(
        offered(&frames),
        vec![
            (0, CHUNK as u32),
            (CHUNK as u64, CHUNK as u32),
            (2 * CHUNK as u64, 2_048)
        ],
        "the write pipelines its three chunks"
    );

    // The first and the third are answered; the second never is, and lapses.
    peer.send(&write_response(mid_of(&frames[0]), CHUNK as u32))
        .await;
    peer.send(&write_response(mid_of(&frames[2]), 2_048)).await;

    let error = writing
        .await
        .unwrap()
        .expect_err("the second chunk never answered");
    match error {
        Error::WritePartial { written, source } => {
            assert_eq!(
                written,
                CHUNK as u64,
                "the contiguous prefix, not the {} bytes acknowledged in total",
                CHUNK + 2_048
            );
            assert!(
                matches!(*source, Error::RequestTimeout),
                "the write stopped on the lapse: {source}"
            );
        }
        other => panic!("expected a partial write, got {other}"),
    }
    // The handle a caller passed reads the same prefix afterwards, the drain
    // having already made the two one number.
    progress.completed().await;
    assert_eq!(progress.written(), CHUNK as u64);
    assert_eq!(data.len(), SPAN);
}

/// **Invariant 4, the caller drop, and Orphaned's first exit: an arrival that
/// completes the reply.**
///
/// The future is dropped with all three chunks on the wire. Nothing reaches the
/// caller that way ever, so what it reads is the handle — and the ranges are
/// recorded *after* the drop, by the connection actor applying what the caller
/// arranged to outlive the request.
///
/// **What a plausible wrong implementation does.** One that records ranges in
/// the awaiting future reports 0, the future being gone before any reply
/// arrived. One without a completion signal leaves the caller reading a handle
/// that is still growing, with no way to tell a final prefix from a partial one.
#[tokio::test(start_paused = true)]
async fn invariant_4_a_dropped_write_records_through_the_handle() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let file = open(&tree, &mut peer).await;

    let progress = WriteProgress::new();
    let data = vec![0xCD; SPAN];
    // Boxed rather than `tokio::pin!`ed: pinning shadows the future with a
    // `Pin<&mut _>`, and dropping *that* drops the borrow rather than the
    // future, so the caller would never actually give up.
    let mut writing = Box::pin(file.write_all_at(&data, 0, Some(progress.clone())));
    // Drives the write far enough to put its chunks on the wire, and no further.
    let _ = timeout(Duration::from_millis(1), &mut writing).await;

    let frames = peer.drain().await;
    assert_eq!(frames.len(), 3, "three chunks reached the wire");
    assert_eq!(progress.written(), 0, "nothing is acknowledged yet");

    // The caller gives up. The requests stay outstanding at the server.
    drop(writing);

    for frame in &frames {
        let (_, length) = write_request(frame);
        peer.send(&write_response(mid_of(frame), length)).await;
    }

    progress.completed().await;
    assert_eq!(
        progress.written(),
        SPAN as u64,
        "every chunk was acknowledged after the drop, and the handle says so"
    );
}

/// **Orphaned's first exit again, in its other half: an arrival that ends the
/// request without completing the reply.**
///
/// The middle chunk is answered with the bodyless shape SMB1 answers a failed
/// command with — `WordCount = 0`, the header's status the whole of what it
/// says. The request ends on that arrival, so it leaves the chunk group and the
/// signal fires; it acknowledges nothing, so it records nothing, and the prefix
/// stops at the chunk before it.
///
/// **What a plausible wrong implementation does.** One that only leaves the
/// group on a *readable* reply hangs `completed()` for ever on this frame. One
/// that records the chunk's requested length whenever the request ends reports
/// 262,144 bytes for a write of which 130,048 landed.
#[tokio::test(start_paused = true)]
async fn invariant_4_an_arrival_that_corrupts_the_reply_still_leaves_the_group() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let file = open(&tree, &mut peer).await;

    let progress = WriteProgress::new();
    let data = vec![0xCD; SPAN];
    // Boxed rather than `tokio::pin!`ed: pinning shadows the future with a
    // `Pin<&mut _>`, and dropping *that* drops the borrow rather than the
    // future, so the caller would never actually give up.
    let mut writing = Box::pin(file.write_all_at(&data, 0, Some(progress.clone())));
    let _ = timeout(Duration::from_millis(1), &mut writing).await;
    let frames = peer.drain().await;
    assert_eq!(frames.len(), 3);
    drop(writing);

    peer.send(&write_response(mid_of(&frames[0]), CHUNK as u32))
        .await;
    peer.send(&harness::bodyless(
        WRITE_ANDX,
        NtStatus::INVALID_HANDLE,
        mid_of(&frames[1]),
    ))
    .await;
    peer.send(&write_response(mid_of(&frames[2]), 2_048)).await;

    // `completed()` returning at all is half of what this proves.
    timeout(Duration::from_secs(1), progress.completed())
        .await
        .expect("the group emptied on the corrupting arrival");
    assert_eq!(progress.written(), CHUNK as u64);
}

/// **Orphaned's second exit: the request lapsing on a timeout.**
///
/// One chunk is never answered. It lapses, which stops it charging capacity
/// while it stays in the request table holding its multiplex id — so a signal
/// that waited on the table rather than on the group would hang here, on exactly
/// the case the handle exists for.
///
/// **What a plausible wrong implementation does.** One keying the signal on the
/// request table never fires. One that leaves the group only on a reply never
/// fires either, and a caller resuming a transfer waits for ever rather than
/// resuming.
#[tokio::test(start_paused = true)]
async fn invariant_4_a_lapse_leaves_the_chunk_group() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let file = open(&tree, &mut peer).await;

    let progress = WriteProgress::new();
    let data = vec![0xCD; SPAN];
    // Boxed rather than `tokio::pin!`ed: pinning shadows the future with a
    // `Pin<&mut _>`, and dropping *that* drops the borrow rather than the
    // future, so the caller would never actually give up.
    let mut writing = Box::pin(file.write_all_at(&data, 0, Some(progress.clone())));
    let _ = timeout(Duration::from_millis(1), &mut writing).await;
    let frames = peer.drain().await;
    assert_eq!(frames.len(), 3);
    drop(writing);

    peer.send(&write_response(mid_of(&frames[0]), CHUNK as u32))
        .await;
    peer.send(&write_response(mid_of(&frames[1]), CHUNK as u32))
        .await;
    // The third is left unanswered, and the per-request timeout lapses it.

    timeout(Duration::from_secs(60), progress.completed())
        .await
        .expect("the lapse emptied the group");
    assert_eq!(
        progress.written(),
        2 * CHUNK as u64,
        "the two chunks that were acknowledged, and not the one that lapsed"
    );
}

/// **Orphaned's third exit: the connection dying.**
///
/// The far side hangs up with the write's chunks outstanding. Every request the
/// connection was holding ends, so every chunk leaves the group and the signal
/// fires — which is what stops a caller awaiting it being left waiting on a
/// connection that has gone.
///
/// **What a plausible wrong implementation does.** One that fires the signal
/// only from a reply hangs for ever here, on the case a caller is likeliest to
/// meet in production.
#[tokio::test(start_paused = true)]
async fn invariant_4_the_connection_dying_leaves_the_chunk_group() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let file = open(&tree, &mut peer).await;

    let progress = WriteProgress::new();
    let data = vec![0xCD; SPAN];
    // Boxed rather than `tokio::pin!`ed: pinning shadows the future with a
    // `Pin<&mut _>`, and dropping *that* drops the borrow rather than the
    // future, so the caller would never actually give up.
    let mut writing = Box::pin(file.write_all_at(&data, 0, Some(progress.clone())));
    let _ = timeout(Duration::from_millis(1), &mut writing).await;
    let frames = peer.drain().await;
    assert_eq!(frames.len(), 3);

    peer.send(&write_response(mid_of(&frames[0]), CHUNK as u32))
        .await;
    // Let the first acknowledgement land before the caller gives up, so the
    // prefix has something in it to be final about.
    let _ = timeout(Duration::from_millis(1), &mut writing).await;
    drop(writing);
    peer.hang_up();

    timeout(Duration::from_secs(1), progress.completed())
        .await
        .expect("the connection dying emptied the group");
    assert_eq!(progress.written(), CHUNK as u64);
}

/// **A range is recorded from the reply, not from the request.**
///
/// The chunk asks to write 130,048 bytes and the server acknowledges 1,000. The
/// remainder is re-issued from the first unacknowledged byte and then never
/// answered, so the write lapses with 1,000 bytes as its prefix.
///
/// **What a plausible wrong implementation does.** One recording what the chunk
/// asked to write reports 130,048 bytes as having reached the server, which is
/// the one thing the prefix exists to get right: a caller resuming there skips
/// 129,048 bytes it never wrote.
#[tokio::test(start_paused = true)]
async fn invariant_4_a_short_acknowledgement_records_what_the_reply_said() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let file = open(&tree, &mut peer).await;

    let progress = WriteProgress::new();
    let writing = tokio::spawn({
        let progress = progress.clone();
        async move {
            file.write_all_at(&vec![0xEF; CHUNK], 0, Some(progress))
                .await
        }
    });

    let first = peer.frame().await;
    assert_eq!(write_request(&first), (0, CHUNK as u32));
    peer.send(&write_response(mid_of(&first), 1_000)).await;

    // The remainder is re-issued from the first unacknowledged byte, and left
    // unanswered.
    let second = peer.frame().await;
    assert_eq!(
        write_request(&second),
        (1_000, CHUNK as u32 - 1_000),
        "the remainder is re-issued, not the whole chunk"
    );

    let error = writing.await.unwrap().expect_err("the remainder lapsed");
    match error {
        Error::WritePartial { written, .. } => assert_eq!(written, 1_000),
        other => panic!("expected a partial write, got {other}"),
    }
}

/// **One handle serves one write**, and a second registration is an `Err` rather
/// than a panic — recoverable caller misuse.
///
/// A prefix computed across two writes to different offsets means nothing, and a
/// completion signal that waits for both answers neither.
#[tokio::test(start_paused = true)]
async fn invariant_4_one_handle_serves_one_write() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let file = open(&tree, &mut peer).await;

    let progress = WriteProgress::new();
    let writing = tokio::spawn({
        let progress = progress.clone();
        async move {
            let first = file
                .write_all_at(&[1, 2, 3], 0, Some(progress.clone()))
                .await;
            let second = file.write_all_at(&[4, 5, 6], 64, Some(progress)).await;
            (first, second)
        }
    });

    let frame = peer.frame().await;
    peer.send(&write_response(mid_of(&frame), 3)).await;

    let (first, second) = writing.await.unwrap();
    first.expect("the first write is the one the handle serves");
    assert!(
        matches!(second, Err(Error::ProgressInUse)),
        "the second registration is refused: {second:?}"
    );
    // The file was dropped with the task, so what remains is its close and
    // nothing else: the refused write put no frame on the wire.
    let rest = peer.drain().await;
    assert!(
        rest.iter().all(|frame| command_of(frame) != WRITE_ANDX),
        "the refused write sent nothing"
    );
}

/// **A prefix already declared final may not grow afterwards**, a caller having
/// possibly resumed from it. A rule that turned on whether the signal had fired
/// first would be a race.
#[tokio::test(start_paused = true)]
async fn invariant_4_a_final_prefix_does_not_grow() {
    let (tree, mut peer) = tree(large_io(), Timeouts::default());
    let file = open(&tree, &mut peer).await;

    let progress = WriteProgress::new();
    let data = vec![0xCD; SPAN];
    // Boxed rather than `tokio::pin!`ed: pinning shadows the future with a
    // `Pin<&mut _>`, and dropping *that* drops the borrow rather than the
    // future, so the caller would never actually give up.
    let mut writing = Box::pin(file.write_all_at(&data, 0, Some(progress.clone())));
    let _ = timeout(Duration::from_millis(1), &mut writing).await;
    let frames = peer.drain().await;
    drop(writing);

    // Only the first chunk is answered; the other two lapse, which settles the
    // handle at 130,048.
    peer.send(&write_response(mid_of(&frames[0]), CHUNK as u32))
        .await;
    timeout(Duration::from_secs(60), progress.completed())
        .await
        .expect("the lapses settled the handle");
    assert_eq!(progress.written(), CHUNK as u64);

    // A reply arriving after the give-up records nothing: it reaches a request
    // that has already lapsed, and is logged there.
    peer.send(&write_response(mid_of(&frames[1]), CHUNK as u32))
        .await;
    let _ = peer.next_frame().await;
    assert_eq!(
        progress.written(),
        CHUNK as u64,
        "the prefix a caller may have resumed from does not move"
    );
}
