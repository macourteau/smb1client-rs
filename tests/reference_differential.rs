//! What CI asserts for the step-4 differential run.
//!
//! Build order step 4 requires `session.rs`, `tree.rs` and `resource/` to be
//! differentially tested against the Go reference library on the acceptance
//! container. **That run is development-time and never a CI job** — nothing in
//! CI checks out the Go repository — so its comparisons are committed as
//! expected values in `vectors/reference-differential.txt` and this file is
//! what asserts them, the same arrangement `auth/` uses at build order step 3.
//!
//! The run itself drove both clients against the seeded container through
//! frame-splitting relays and compared what each put on the wire. Every value
//! this file reads back was read off those frames. The assertions below are
//! offline: they drive the port over the connection's test seam with the
//! container's own negotiated parameters injected, so the frames compared are
//! the frames that run captured, without a server to reach.
//!
//! Three of the file's entries are asserted in `handshake.rs` instead — the
//! session's advertised `MaxBufferSize` and its capability word — that file
//! owning the handshake's scripted server.

use std::collections::HashMap;
use std::time::Duration;

use smb1client::connection::{Negotiated, Timeouts};
use smb1client::tree::OpenOptions;

mod harness;

use harness::{
    CLOSE, FIND_CLOSE2, NT_CREATE_ANDX, READ_ANDX, RENAME, TRANSACTION2, WRITE_ANDX, area_of,
    bodyless, chain, command_of, create_response, find_first_parameters, find_next_parameters,
    large_io, read_request, read_response, small_io, trans2_parameters, trans2_subcommand,
    transaction_response, tree, word_at, words_of, write_request, write_response,
};
use smb1client::NtStatus;

/// Reads a `name = value` vector file.
fn vectors(name: &str) -> HashMap<String, String> {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    text.lines()
        .filter_map(|line| line.split('#').next())
        .filter_map(|line| line.split_once(" = "))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect()
}

fn text<'a>(vectors: &'a HashMap<String, String>, name: &str) -> &'a str {
    vectors
        .get(name)
        .unwrap_or_else(|| panic!("vector {name} is missing"))
}

/// A vector holding a number, in decimal or with an `0x` prefix.
fn number(vectors: &HashMap<String, String>, name: &str) -> u64 {
    let raw = text(vectors, name);
    match raw.strip_prefix("0x") {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => raw.parse(),
    }
    .unwrap_or_else(|e| panic!("vector {name} = {raw}: {e}"))
}

/// A vector holding a comma-separated chunk sequence.
fn chunks(vectors: &HashMap<String, String>, name: &str) -> Vec<u32> {
    text(vectors, name)
        .split(',')
        .map(|part| part.trim().parse().expect("a chunk size"))
        .collect()
}

/// What the acceptance container negotiated with both clients during the run.
///
/// It is not [`harness::large_io`]: that one carries a 65,535-byte buffer, and
/// what the container advertises is 16,644. The difference is the whole of the
/// chunk-size comparison below, since 16,644 less the reservation is the number
/// the reference's sequential paths clamp to.
fn container(vectors: &HashMap<String, String>) -> Negotiated {
    Negotiated {
        max_mpx_count: 50,
        max_buffer_size: number(vectors, "container_negotiated_max_buffer_size") as u32,
        capabilities: 0x8080_F3FD,
    }
}

fn timeouts() -> Timeouts {
    Timeouts {
        per_request: Duration::from_secs(30),
        overall: Duration::from_secs(60),
    }
}

/// The `TRANS2` sizing fields, off a request's word block.
fn trans2_sizing(frame: &[u8]) -> (u16, u16, u8, u16, u32) {
    let words = words_of(frame);
    (
        word_at(frame, 2), // MaxParameterCount
        word_at(frame, 3), // MaxDataCount
        words[8],          // MaxSetupCount
        word_at(frame, 5), // Flags
        u32::from_le_bytes([words[12], words[13], words[14], words[15]]), // Timeout
    )
}

/// Every field of an `NT_CREATE_ANDX` request this comparison pins.
struct Create {
    desired_access: u32,
    file_attributes: u32,
    share_access: u32,
    disposition: u32,
    options: u32,
    flags: u32,
    root_directory_fid: u32,
    allocation_size: u64,
    impersonation: u32,
    security_flags: u8,
}

fn create_fields(frame: &[u8]) -> Create {
    let words = words_of(frame);
    let at32 = |index: usize| {
        u32::from_le_bytes([
            words[index],
            words[index + 1],
            words[index + 2],
            words[index + 3],
        ])
    };
    Create {
        flags: at32(7),
        root_directory_fid: at32(11),
        desired_access: at32(15),
        allocation_size: u64::from(at32(19)) | (u64::from(at32(23)) << 32),
        file_attributes: at32(27),
        share_access: at32(31),
        disposition: at32(35),
        options: at32(39),
        impersonation: at32(43),
        security_flags: words[47],
    }
}

/// The chunk sizes a whole-file read of `length` bytes asks for, in order.
async fn read_chunk_sizes(negotiated: Negotiated, length: usize) -> Vec<u32> {
    let (tree, mut peer) = tree(negotiated, timeouts());
    let payload = vec![0xA5u8; length];
    let task = tokio::spawn(async move { tree.read("file.bin").await });

    peer.answer(|frame, mid| {
        assert_eq!(command_of(frame), NT_CREATE_ANDX);
        create_response(mid, 0x40, length as u64, false)
    })
    .await;

    let mut sizes = Vec::new();
    let mut covered = 0usize;
    while covered < length {
        let frame = peer.frame().await;
        assert_eq!(command_of(&frame), READ_ANDX);
        let (offset, count) = read_request(&frame);
        sizes.push(count);
        let end = (offset as usize + count as usize).min(length);
        let served = &payload[offset as usize..end];
        covered += served.len();
        let mid = harness::mid_of(&frame);
        peer.send(&read_response(mid, served)).await;
    }
    peer.answer(|frame, mid| {
        assert_eq!(command_of(frame), CLOSE);
        bodyless(CLOSE, NtStatus::SUCCESS, mid)
    })
    .await;
    task.await.expect("the read task").expect("the read");
    sizes
}

/// The chunk sizes a `write_all_at` of `length` bytes offers, in order.
async fn write_chunk_sizes(negotiated: Negotiated, length: usize) -> Vec<u32> {
    let (tree, mut peer) = tree(negotiated, timeouts());
    let payload = vec![0x5Au8; length];
    let task = tokio::spawn(async move {
        let file = tree
            .open_with("file.bin", &OpenOptions::new().read(true).write(true))
            .await?;
        file.write_all_at(&payload, 0, None).await
    });

    peer.answer_open(0x41, 0).await;

    let mut sizes = Vec::new();
    let mut acknowledged = 0usize;
    while acknowledged < length {
        let frame = peer.frame().await;
        assert_eq!(command_of(&frame), WRITE_ANDX);
        let (_, count) = write_request(&frame);
        sizes.push(count);
        acknowledged += count as usize;
        let mid = harness::mid_of(&frame);
        peer.send(&write_response(mid, count)).await;
    }
    task.await.expect("the write task").expect("the write");
    sizes
}

/// The sizing rule every transaction the port builds is held to.
///
/// A wrong implementation passes this only by keeping the two fields at the
/// pinned pair on **every** TRANS2 subcommand: the ceiling is Windows'
/// measured one and it rejects on the sum alone, so a per-subcommand value that
/// happens to fit here would still have to fit there.
#[tokio::test]
async fn every_transaction_is_sized_under_the_measured_ceiling() {
    let v = vectors("reference-differential.txt");
    let ceiling = number(&v, "measured_windows_transaction_ceiling");
    let expected_parameter = number(&v, "port_trans2_max_parameter_count") as u16;
    let expected_data = number(&v, "port_trans2_max_data_count") as u16;

    assert!(
        number(&v, "reference_trans2_sum") > ceiling,
        "the reference's own sum must be over the ceiling, or this vector pins nothing"
    );

    let (tree, mut peer) = tree(container(&v), timeouts());
    let task = tokio::spawn(async move {
        let _ = tree.metadata("alpha.txt").await;
        let _ = tree.statistics().await;
        let mut listing = tree.read_dir("bigdir").await?;
        while listing.next_entry().await?.is_some() {}
        listing.close().await
    });

    // Answer whatever transaction arrives with an empty reply, and count. A
    // failure of the operation does not matter here: the request is the
    // observation.
    let mut seen = 0;
    for _ in 0..8 {
        let Some(frame) = peer.next_frame().await else {
            break;
        };
        if command_of(&frame) != TRANSACTION2 {
            continue;
        }
        seen += 1;
        let (parameter, data, setup, flags, timeout) = trans2_sizing(&frame);
        assert_eq!(
            parameter,
            expected_parameter,
            "MaxParameterCount on subcommand {:#06x}",
            trans2_subcommand(&frame)
        );
        assert_eq!(data, expected_data);
        assert_eq!(u64::from(parameter) + u64::from(data), ceiling - 988);
        assert!(u64::from(parameter) + u64::from(data) <= ceiling);
        assert_eq!(u64::from(setup), number(&v, "port_trans2_max_setup_count"));
        assert_eq!(u64::from(flags), number(&v, "port_trans2_flags"));
        assert_eq!(u64::from(timeout), number(&v, "port_trans2_timeout"));

        let mid = harness::mid_of(&frame);
        peer.send(&bodyless(TRANSACTION2, NtStatus::new(0xC000_0225), mid))
            .await;
    }
    assert!(seen >= 3, "only {seen} transactions reached the seam");
    let _ = task.await;
}

/// The FIND requests, including the one addition the port makes to what the
/// reference sends.
///
/// A wrong implementation passes only by setting `SMB_FIND_CLOSE_AT_EOS` on the
/// FIND_NEXT2 as well as the FIND_FIRST2 — the reference sets it on the first
/// alone, which is half of why no listing of its longer than one batch closes
/// its search.
#[tokio::test]
async fn the_find_requests_carry_the_pinned_fields() {
    let v = vectors("reference-differential.txt");
    let (tree, mut peer) = tree(container(&v), timeouts());

    let task = tokio::spawn(async move {
        let mut listing = tree.read_dir("bigdir").await?;
        let mut names = Vec::new();
        while let Some(entry) = listing.next_entry().await? {
            names.push(entry.name().to_owned());
        }
        listing.close().await?;
        Ok::<_, smb1client::Error>(names)
    });

    // The FIND_FIRST2, answered with one page that does not end the search.
    let first = peer
        .answer(|frame, mid| {
            assert_eq!(command_of(frame), TRANSACTION2);
            transaction_response(
                mid,
                NtStatus::SUCCESS,
                &find_first_parameters(0x0100, 2, false),
                &chain(&[("a.txt", false), ("b.txt", false)]),
            )
        })
        .await;
    let parameters = trans2_parameters(&first);
    assert_eq!(trans2_subcommand(&first), 0x0001);
    assert_eq!(
        u64::from(u16::from_le_bytes([parameters[0], parameters[1]])),
        number(&v, "port_find_first2_search_attributes")
    );
    assert_eq!(
        u64::from(u16::from_le_bytes([parameters[2], parameters[3]])),
        number(&v, "port_find_first2_search_count")
    );
    assert_eq!(
        u64::from(u16::from_le_bytes([parameters[4], parameters[5]])),
        number(&v, "port_find_first2_flags")
    );
    assert_eq!(
        u64::from(u16::from_le_bytes([parameters[6], parameters[7]])),
        number(&v, "port_find_first2_information_level")
    );
    assert_eq!(
        utf16(&parameters[12..]),
        text(&v, "port_find_first2_pattern_subdirectory")
    );

    // The FIND_NEXT2, answered with the terminator.
    let next = peer
        .answer(|frame, mid| {
            assert_eq!(command_of(frame), TRANSACTION2);
            transaction_response(
                mid,
                NtStatus::SUCCESS,
                &find_next_parameters(1, true),
                &chain(&[("c.txt", false)]),
            )
        })
        .await;
    let parameters = trans2_parameters(&next);
    assert_eq!(trans2_subcommand(&next), 0x0002);
    assert_eq!(
        u64::from(u16::from_le_bytes([parameters[2], parameters[3]])),
        number(&v, "port_find_next2_search_count")
    );
    assert_eq!(
        u64::from(u16::from_le_bytes([parameters[4], parameters[5]])),
        number(&v, "port_find_next2_information_level")
    );
    assert_eq!(
        u64::from(u32::from_le_bytes([
            parameters[6],
            parameters[7],
            parameters[8],
            parameters[9]
        ])),
        number(&v, "port_find_next2_resume_key")
    );
    let flags = u64::from(u16::from_le_bytes([parameters[10], parameters[11]]));
    assert_eq!(flags, number(&v, "port_find_next2_flags"));
    assert_ne!(
        flags,
        number(&v, "reference_find_next2_flags"),
        "the reference's FIND_NEXT2 flags are the known-wrong value"
    );
    // The bit the reference omits is the one the port adds.
    assert_eq!(
        flags ^ number(&v, "reference_find_next2_flags"),
        number(&v, "port_find_first2_flags")
    );

    let names = task.await.expect("the listing task").expect("the listing");
    assert_eq!(names, ["a.txt", "b.txt", "c.txt"]);

    // The share root's pattern is the asymmetric one the design inherits
    // deliberately: a leading backslash where a path inside the share has none.
    let (root_tree, mut root_peer) = harness::tree(container(&v), timeouts());
    let root = tokio::spawn(async move { root_tree.read_dir("").await.map(|_| ()) });
    let first = root_peer
        .answer(|frame, mid| {
            assert_eq!(command_of(frame), TRANSACTION2);
            transaction_response(
                mid,
                NtStatus::SUCCESS,
                &find_first_parameters(0x0101, 0, true),
                b"",
            )
        })
        .await;
    assert_eq!(
        utf16(&trans2_parameters(&first)[12..]),
        text(&v, "port_find_first2_pattern_root")
    );
    let _ = root.await;

    // Drained to end-of-stream, so no search is left to release: the request
    // that ended it carried `SMB_FIND_CLOSE_AT_EOS`, and the server released
    // the search when it processed that. Whatever else the tree sends as it is
    // dropped, an `SMB_COM_FIND_CLOSE2` is not among it.
    let trailing = peer.drain().await;
    assert_eq!(
        u64::from(
            trailing
                .iter()
                .filter(|frame| command_of(frame) == FIND_CLOSE2)
                .count() as u32
        ),
        number(&v, "port_find_close2_on_drained_listing")
    );
}

/// A listing abandoned before end-of-stream is closed with the command the
/// reference never sends at all.
#[tokio::test]
async fn a_dropped_listing_sends_the_find_close2_the_reference_never_sends() {
    let v = vectors("reference-differential.txt");
    let (tree, mut peer) = tree(container(&v), timeouts());

    let task = tokio::spawn(async move {
        let mut listing = tree.read_dir("bigdir").await?;
        listing.next_entry().await?;
        listing.close().await
    });

    peer.answer(|frame, mid| {
        assert_eq!(command_of(frame), TRANSACTION2);
        transaction_response(
            mid,
            NtStatus::SUCCESS,
            &find_first_parameters(0x0100, 2, false),
            &chain(&[("a.txt", false), ("b.txt", false)]),
        )
    })
    .await;

    let close = peer
        .answer(|frame, mid| {
            assert_eq!(command_of(frame), FIND_CLOSE2);
            bodyless(FIND_CLOSE2, NtStatus::SUCCESS, mid)
        })
        .await;
    assert_eq!(
        u64::from(words_of(&close).len() as u32 / 2),
        number(&v, "port_find_close2_word_count")
    );
    assert_eq!(word_at(&close, 0), 0x0100, "the search id it was given");
    assert_eq!(
        u64::from(area_of(&close).len() as u32),
        number(&v, "port_find_close2_byte_count")
    );

    task.await.expect("the close task").expect("the close");
    // Exactly one, never two: the close is not also enqueued by the drop.
    let trailing = peer.drain().await;
    assert!(
        trailing
            .iter()
            .all(|frame| command_of(frame) != FIND_CLOSE2),
        "a second SMB_COM_FIND_CLOSE2 followed the first"
    );
}

/// The `NT_CREATE_ANDX` field matrix, one open per verb.
///
/// A wrong implementation passes only by sending `FILE_SHARE_DELETE` in every
/// share mode and by asking for no right it does not use: the `SYNCHRONIZE`
/// assertion is what the reference would fail on every one of its six.
#[tokio::test]
async fn the_open_field_matrix_holds_for_every_verb() {
    let v = vectors("reference-differential.txt");
    let synchronize = number(&v, "synchronize_right") as u32;

    for (verb, prefix) in [
        ("open", "port_open_read"),
        ("open_with", "port_open_read_write"),
        ("write", "port_create_truncate"),
        ("create_dir", "port_create_dir"),
        ("remove_file", "port_remove_file"),
        ("remove_dir", "port_remove_dir"),
    ] {
        let (tree, mut peer) = tree(container(&v), timeouts());
        let task = tokio::spawn(async move {
            match verb {
                "open" => tree.open("path.bin").await.map(|_| ()),
                "open_with" => tree
                    .open_with("path.bin", &OpenOptions::new().read(true).write(true))
                    .await
                    .map(|_| ()),
                "write" => tree.write("path.bin", b"").await,
                "create_dir" => tree.create_dir("path.bin").await,
                "remove_file" => tree.remove_file("path.bin").await,
                _ => tree.remove_dir("path.bin").await,
            }
        });

        let frame = peer.frame().await;
        assert_eq!(command_of(&frame), NT_CREATE_ANDX, "{verb}");
        let fields = create_fields(&frame);

        assert_eq!(
            u64::from(fields.desired_access),
            number(&v, &format!("{prefix}_desired_access")),
            "{verb} DesiredAccess"
        );
        assert_eq!(
            u64::from(fields.disposition),
            number(&v, &format!("{prefix}_disposition")),
            "{verb} CreateDisposition"
        );
        assert_eq!(
            u64::from(fields.options),
            number(&v, &format!("{prefix}_options")),
            "{verb} CreateOptions"
        );
        assert_eq!(
            fields.desired_access & synchronize,
            0,
            "{verb} asked for SYNCHRONIZE, which nothing in this crate waits on"
        );
        assert_eq!(
            u64::from(fields.file_attributes),
            number(&v, &format!("{prefix}_file_attributes")),
            "{verb} FileAttributes"
        );
        assert_eq!(
            u64::from(fields.share_access),
            number(&v, "port_create_share_access"),
            "{verb} ShareAccess"
        );
        assert_ne!(
            u64::from(fields.share_access),
            number(&v, "reference_non_delete_share_access"),
            "{verb} sent the reference's share mode, which denies a deleter"
        );
        assert_eq!(u64::from(fields.flags), number(&v, "port_create_flags"));
        assert_eq!(
            u64::from(fields.root_directory_fid),
            number(&v, "port_create_root_directory_fid")
        );
        assert_eq!(
            fields.allocation_size,
            number(&v, "port_create_allocation_size")
        );
        assert_eq!(
            u64::from(fields.impersonation),
            number(&v, "port_create_impersonation_level")
        );
        assert_eq!(
            u64::from(fields.security_flags),
            number(&v, "port_create_security_flags")
        );

        let mid = harness::mid_of(&frame);
        peer.send(&create_response(mid, 0x42, 0, verb.contains("dir")))
            .await;
        let _ = peer.drain().await;
        task.abort();
    }
}

/// `SMB_COM_RENAME`: the attributes, and both names carrying the leading
/// backslash this one command puts on the wire.
#[tokio::test]
async fn rename_carries_the_search_attributes_and_both_leading_backslashes() {
    let v = vectors("reference-differential.txt");
    let (tree, mut peer) = tree(container(&v), timeouts());
    let task = tokio::spawn(async move { tree.rename("direction/a.bin", "direction/b.bin").await });

    let frame = peer
        .answer(|frame, mid| {
            assert_eq!(command_of(frame), RENAME);
            bodyless(RENAME, NtStatus::SUCCESS, mid)
        })
        .await;
    assert_eq!(
        u64::from(word_at(&frame, 0)),
        number(&v, "port_rename_search_attributes")
    );
    assert_eq!(
        hex::encode(area_of(&frame)),
        text(&v, "port_rename_byte_area_hex")
    );
    task.await.expect("the rename task").expect("the rename");
}

/// Chunk size — the disagreement neither side is the reference for.
///
/// What is asserted is that the port has **one** rule: the same chunk size
/// whichever side of the pipelining thresholds a transfer falls on. The
/// reference reaches three different answers on this one connection, and
/// `reference_sequential_clamp` is where two of them land — which is where the
/// port lands only when the server offers no large-I/O capability at all.
#[tokio::test]
async fn the_chunk_size_is_one_rule_whatever_the_transfer() {
    let v = vectors("reference-differential.txt");
    let negotiated = container(&v);
    let large = number(&v, "port_chunk_size_with_large_io") as u32;
    let clamp = number(&v, "reference_sequential_clamp") as u32;

    assert_eq!(
        clamp,
        negotiated.max_buffer_size - number(&v, "protocol_overhead_reservation") as u32,
        "the clamp is the negotiated buffer less the reservation, or the comparison is not this connection's"
    );

    let (large_tree, _large_peer) = tree(negotiated, timeouts());
    assert_eq!(
        large_tree.connection().read_chunk_size() as u64,
        u64::from(large)
    );
    assert_eq!(
        large_tree.connection().write_chunk_size() as u64,
        u64::from(large)
    );

    // Under both thresholds, where the reference clamps and the port does not.
    let read_100k = read_chunk_sizes(negotiated, 100 * 1024).await;
    assert_eq!(read_100k, chunks(&v, "port_read_chunks_100k"));
    assert_ne!(read_100k, chunks(&v, "reference_read_chunks_100k"));
    assert!(!read_100k.contains(&clamp));

    let write_100k = write_chunk_sizes(negotiated, 100 * 1024).await;
    assert_eq!(write_100k, chunks(&v, "port_write_chunks_100k"));
    assert_ne!(write_100k, chunks(&v, "reference_write_chunks_100k"));

    // Over both, where the two agree.
    assert_eq!(
        read_chunk_sizes(negotiated, 512 * 1024).await,
        chunks(&v, "port_read_chunks_512k")
    );
    let write_512k = write_chunk_sizes(negotiated, 512 * 1024).await;
    assert_eq!(write_512k, chunks(&v, "port_write_chunks_512k"));
    assert_eq!(write_512k, chunks(&v, "reference_write_chunks_512k"));

    // The one rule's other two cases. A server offering neither capability is
    // the only thing that puts the port on the reference's clamp.
    let (small, _small_peer) = tree(small_io(negotiated.max_buffer_size), timeouts());
    assert_eq!(
        small.connection().read_chunk_size() as u64,
        number(&v, "port_chunk_size_without_large_io")
    );
    assert_eq!(
        small.connection().read_chunk_size() as u32,
        clamp,
        "the capability-less case is where the port reaches the reference's number"
    );

    // And [`harness::large_io`]'s own buffer is not the container's, which is
    // why this file injects its own negotiated parameters.
    assert_ne!(large_io().max_buffer_size, negotiated.max_buffer_size);
}

/// The fill loop, on the wire.
///
/// A chunk answered short is re-issued for the bytes it did not return. The
/// reference stops at the first short chunk and calls it end of file, which is
/// known-wrong item 8; a wrong implementation here sends one request where the
/// vector pins two.
#[tokio::test]
async fn a_short_chunk_is_reissued_rather_than_read_as_end_of_file() {
    let v = vectors("reference-differential.txt");
    let expected = chunks(&v, "port_read_chunks_short_far_end");
    let (tree, mut peer) = tree(container(&v), timeouts());

    let task = tokio::spawn(async move {
        let file = tree.open("file.bin").await?;
        let mut buffer = [0u8; 32];
        file.read_exact_at(&mut buffer, 0).await
    });

    peer.answer_open(0x43, 32).await;

    let mut sizes = Vec::new();
    // The first chunk is served 8 of the 32 asked for; the second is served
    // nothing, which is the loop's no-progress guard and ends it.
    let first = peer.frame().await;
    assert_eq!(command_of(&first), READ_ANDX);
    sizes.push(read_request(&first).1);
    let mid = harness::mid_of(&first);
    peer.send(&read_response(mid, &[0u8; 8])).await;

    let second = peer.frame().await;
    assert_eq!(command_of(&second), READ_ANDX);
    let (offset, count) = read_request(&second);
    sizes.push(count);
    assert_eq!(
        offset, 8,
        "the re-issue starts where the short answer ended"
    );
    let mid = harness::mid_of(&second);
    peer.send(&read_response(mid, &[])).await;

    assert_eq!(sizes, expected);
    assert_eq!(
        chunks(&v, "reference_read_chunks_short_far_end").len(),
        1,
        "the reference sends one and calls the short answer the end"
    );
    task.await
        .expect("the read task")
        .expect_err("a span that cannot be filled is an error");
}

fn utf16(bytes: &[u8]) -> String {
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .take_while(|unit| *unit != 0)
        .collect();
    String::from_utf16(&units).expect("a decodable pattern")
}
