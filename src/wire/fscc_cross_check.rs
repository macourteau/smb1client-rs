//! What CI asserts for the MS-FSCC cross-validation.
//!
//! The design considered `smb-fscc` as a dev-dependency test oracle for its
//! independently validated MS-FSCC struct layouts and rejected it: pinning does
//! not stop a bot raising pull requests, and every `0.x` minor would be held
//! for a human — the cost that rejected the smb-rs family as a runtime
//! dependency, arriving through the development door instead. What it
//! prescribes is the cross-validation run once and its results committed as
//! plain expected values, which keeps the evidence and drops the subscription.
//!
//! That run happened in a scratch copy of this crate outside the repository,
//! against `smb-fscc 0.11.2`, over the committed fixture bytes. Every field
//! this module reads back agreed with it. There is no manifest entry for that
//! crate here and there is not meant to be one.
//!
//! `tests/vectors/ms-fscc-cross-check.txt` carries the values and also the
//! five places the crate could not speak to this port's inputs, each measured
//! during the run rather than assumed. This module asserts both halves: what
//! the decoders produce, and — for the two that are properties of the corpus
//! rather than of the absent crate — that the reason they could not be
//! validated still holds.

use std::collections::HashMap;

use super::find::{self, MIN_ENTRY_LEN};
use super::fixtures;
use super::info;

/// Reads a `name = value` vector file.
fn vectors(name: &str) -> HashMap<String, String> {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{path}: {error}"));
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
fn number(vectors: &HashMap<String, String>, name: &str) -> i128 {
    let raw = text(vectors, name);
    match raw.strip_prefix("0x") {
        Some(hex) => i128::from_str_radix(hex, 16),
        None => raw.parse(),
    }
    .unwrap_or_else(|error| panic!("vector {name} = {raw}: {error}"))
}

fn flag(vectors: &HashMap<String, String>, name: &str) -> bool {
    match text(vectors, name) {
        "true" => true,
        "false" => false,
        other => panic!("vector {name} = {other} is not a boolean"),
    }
}

/// The data block of a TRANS2 reply frame, read off the offsets it declares.
fn trans2_data(relative: &str) -> Vec<u8> {
    let (_, body) = fixtures::frame(relative);
    let word_count = usize::from(body[32]);
    let words = &body[33..33 + word_count * 2];
    let count = usize::from(u16::from_le_bytes([words[12], words[13]]));
    let offset = usize::from(u16::from_le_bytes([words[14], words[15]]));
    body[offset..offset + count].to_vec()
}

/// The two-message FIND_FIRST2 reply of the fragmented corpus, reassembled.
///
/// An entry straddles the boundary between them, so the walk has to be over
/// the joined buffer and never over one message.
fn fragmented_find_data() -> Vec<u8> {
    let mut data = trans2_data("capture-frag/0010-s2c-cmd32.bin");
    data.extend_from_slice(&trans2_data("capture-frag/0011-s2c-cmd32.bin"));
    data
}

/// The entry chain against the values the cross-validation produced.
///
/// A wrong implementation passes this only by having every field of
/// `SMB_FIND_FILE_BOTH_DIRECTORY_INFO` at the offset MS-FSCC gives it: the
/// values are real server bytes read back by a decoder written against that
/// specification and not against this one, so a field displaced by so much as
/// four bytes reports a different number here. The two servers are in it for
/// the same reason — Samba pads its entries to four bytes and Windows mostly
/// to eight, so a walker that had learnt one stride fails the other.
#[test]
fn the_directory_entry_layout_matches_ms_fscc() {
    let vectors = vectors("ms-fscc-cross-check.txt");

    assert_eq!(
        MIN_ENTRY_LEN as i128,
        number(&vectors, "entry_fixed_length"),
        "the fixed part of an entry is the four-byte NextEntryOffset plus MS-FSCC's ninety"
    );

    for (label, data) in [
        ("samba_root", trans2_data("capture/0010-s2c-cmd32.bin")),
        (
            "windows_root",
            trans2_data("capture-win-b/0012-s2c-cmd32.bin"),
        ),
        ("samba_fragmented", fragmented_find_data()),
    ] {
        let expected = number(&vectors, &format!("{label}_entry_count"));
        let entries = find::walk_entries(&data, expected as u16)
            .unwrap_or_else(|error| panic!("{label}: {error}"));
        assert_eq!(entries.len() as i128, expected, "{label}: entry count");

        for (index, entry) in entries.iter().take(3).enumerate() {
            let at = |field: &str| format!("{label}_{index}_{field}");
            assert_eq!(entry.file_name, text(&vectors, &at("name")), "{label} name");
            assert_eq!(
                i128::from(entry.creation_time),
                number(&vectors, &at("creation_time")),
                "{label}[{index}] creation time"
            );
            assert_eq!(
                i128::from(entry.last_access_time),
                number(&vectors, &at("last_access_time"))
            );
            assert_eq!(
                i128::from(entry.last_write_time),
                number(&vectors, &at("last_write_time"))
            );
            assert_eq!(
                i128::from(entry.change_time),
                number(&vectors, &at("change_time"))
            );
            assert_eq!(
                i128::from(entry.end_of_file),
                number(&vectors, &at("end_of_file")),
                "{label}[{index}] end of file"
            );
            assert_eq!(
                i128::from(entry.allocation_size),
                number(&vectors, &at("allocation_size"))
            );
            assert_eq!(
                i128::from(entry.ext_file_attributes),
                number(&vectors, &at("attributes")),
                "{label}[{index}] attributes"
            );
            assert_eq!(i128::from(entry.ea_size), number(&vectors, &at("ea_size")));
        }
    }

    // The `file_index` MS-FSCC calls undefined for filesystems that do not fix
    // a file's position: both servers report zero and the decode is pinned
    // separately from the fields that carry meaning.
    let entries = find::walk_entries(&trans2_data("capture/0010-s2c-cmd32.bin"), 6).unwrap();
    assert!(entries.iter().all(|entry| entry.file_index == 0));

    // The name length the fragmented corpus depends on. Lowering it silently
    // deletes the fragmentation the corpus exists to carry.
    let entries = find::walk_entries(&fragmented_find_data(), 100).unwrap();
    assert_eq!(
        entries[2].file_name.chars().count() as i128,
        number(&vectors, "samba_fragmented_2_name_length")
    );

    // Every entry in the corpus carries an empty short name, which is what
    // limited the crate's oracle over that field to a prefix check.
    assert_eq!(
        entries.iter().all(|entry| entry.short_name.is_empty()),
        flag(&vectors, "corpus_short_names_are_all_empty")
    );
}

/// The two query levels a `Tree::metadata` issues, against the same file.
///
/// They are one assertion in two halves: neither level carries both the times
/// and the size, and the pair here describes `alpha.txt` — the seeded
/// `hello world`, eleven bytes — from two independent directions.
#[test]
fn the_query_levels_match_ms_fscc() {
    let vectors = vectors("ms-fscc-cross-check.txt");

    let data = trans2_data("capture/0012-s2c-cmd32.bin");
    assert_eq!(
        data.len() as i128,
        number(&vectors, "basic_length_on_the_wire")
    );
    assert!(
        number(&vectors, "basic_length_on_the_wire")
            < number(&vectors, "fscc_basic_structure_length"),
        "the SMB1 reply is shorter than MS-FSCC's structure, which is the special case"
    );
    let basic = info::BasicInfo::decode(&data).expect("the basic level decodes");
    assert_eq!(
        i128::from(basic.creation_time.unwrap()),
        number(&vectors, "basic_creation_time")
    );
    assert_eq!(
        i128::from(basic.last_access_time.unwrap()),
        number(&vectors, "basic_last_access_time")
    );
    assert_eq!(
        i128::from(basic.last_write_time.unwrap()),
        number(&vectors, "basic_last_write_time")
    );
    assert_eq!(
        i128::from(basic.change_time.unwrap()),
        number(&vectors, "basic_change_time")
    );
    assert_eq!(
        i128::from(basic.attributes.unwrap()),
        number(&vectors, "basic_attributes")
    );

    let data = trans2_data("capture/0014-s2c-cmd32.bin");
    assert_eq!(
        data.len() as i128,
        number(&vectors, "standard_length_on_the_wire")
    );
    let standard = info::StandardInfo::decode(&data).expect("the standard level decodes");
    assert_eq!(
        i128::from(standard.allocation_size),
        number(&vectors, "standard_allocation_size")
    );
    assert_eq!(
        i128::from(standard.end_of_file),
        number(&vectors, "standard_end_of_file")
    );
    assert_eq!(
        i128::from(standard.number_of_links),
        number(&vectors, "standard_number_of_links")
    );
    assert_eq!(
        standard.delete_pending,
        flag(&vectors, "standard_delete_pending")
    );
    assert_eq!(standard.directory, flag(&vectors, "standard_directory"));

    // The two levels agree about the same file, and the listing agrees with
    // both: three decoders over three different frames, one answer.
    let entries = find::walk_entries(&trans2_data("capture/0010-s2c-cmd32.bin"), 6).unwrap();
    let alpha = entries
        .iter()
        .find(|entry| entry.file_name == text(&vectors, "samba_root_2_name"))
        .expect("the listing holds the file the two queries describe");
    assert_eq!(alpha.end_of_file, standard.end_of_file);
    assert_eq!(alpha.allocation_size, standard.allocation_size);
    assert_eq!(alpha.ext_file_attributes, basic.attributes.unwrap());
    assert_eq!(alpha.last_write_time, basic.last_write_time.unwrap());
}

/// The two levels with no captured frame behind them: the set-file length and
/// the filesystem-size query.
///
/// The length is chosen to catch a byte-order or width mistake in either
/// direction — it is over 32 bits, and every one of its eight bytes differs.
#[test]
fn the_constructed_levels_match_ms_fscc() {
    let vectors = vectors("ms-fscc-cross-check.txt");

    let expected = hex::decode(text(&vectors, "end_of_file_information_hex")).expect("hex");
    let length = number(&vectors, "end_of_file_information_value") as u64;
    assert_eq!(
        expected.len() as i128,
        number(&vectors, "end_of_file_information_length")
    );
    assert_eq!(length.to_le_bytes().to_vec(), expected);
    assert!(length > u64::from(u32::MAX), "and it is over 32 bits");

    let block = hex::decode(text(&vectors, "fs_size_block_hex")).expect("hex");
    let size = info::FsSize::decode_size_info(&block).expect("the fs size level decodes");
    assert_eq!(
        i128::from(size.total_units),
        number(&vectors, "fs_size_total_units")
    );
    assert_eq!(
        i128::from(size.free_units),
        number(&vectors, "fs_size_free_units")
    );
    assert_eq!(
        i128::from(size.sectors_per_unit),
        number(&vectors, "fs_size_sectors_per_unit")
    );
    assert_eq!(
        i128::from(size.bytes_per_sector),
        number(&vectors, "fs_size_bytes_per_sector")
    );
    // The multiplication the verb does once so that every caller does not.
    assert_eq!(
        i128::from(size.bytes(size.total_units)),
        number(&vectors, "fs_size_total_bytes")
    );
}

/// The reason the chained-list container could not be the oracle, still true.
///
/// It reads until a zero `NextEntryOffset`, which SMB2 guarantees and SMB1
/// does not: neither Samba corpus carries one, the last entry's offset running
/// to exactly the end of the data block. So what bounds this crate's walk is
/// the block's length as well as the terminator — and a walker written to the
/// terminator alone runs off the end of both of these frames.
#[test]
fn the_smb1_entry_chain_does_not_carry_smb2s_terminator() {
    let vectors = vectors("ms-fscc-cross-check.txt");

    for (label, data) in [
        ("samba_root", trans2_data("capture/0010-s2c-cmd32.bin")),
        ("samba_fragmented", fragmented_find_data()),
    ] {
        let mut offset = 0usize;
        let mut terminated = false;
        while offset < data.len() {
            let next = u32::from_le_bytes(
                data[offset..offset + 4]
                    .try_into()
                    .expect("four bytes of NextEntryOffset"),
            ) as usize;
            if next == 0 {
                terminated = true;
                break;
            }
            offset += next;
        }
        assert!(!terminated, "{label} carries SMB2's zero terminator");
        assert_eq!(
            offset,
            data.len(),
            "{label}: the chain ends by running out of data, exactly"
        );
    }

    assert!(!flag(&vectors, "samba_root_chain_is_zero_terminated"));
    assert_eq!(
        number(&vectors, "samba_root_chain_last_offset"),
        number(&vectors, "samba_root_chain_data_length")
    );
    assert_eq!(
        trans2_data("capture/0010-s2c-cmd32.bin").len() as i128,
        number(&vectors, "samba_root_chain_data_length")
    );

    // And the walk this crate performs is bounded by both, which is what lets
    // it read these frames at all.
    assert_eq!(
        find::walk_entries(&trans2_data("capture/0010-s2c-cmd32.bin"), 6)
            .expect("the walk is bounded by the data as well as the terminator")
            .len() as i128,
        number(&vectors, "samba_root_entry_count")
    );
}

/// The information-class numbers, which are the other reason the crate could
/// speak to the layouts and not to the levels.
#[test]
fn the_information_levels_are_smb1s_and_not_smb2s() {
    let vectors = vectors("ms-fscc-cross-check.txt");

    for (ours, theirs, actual) in [
        (
            "smb1_both_directory_class",
            "fscc_both_directory_class",
            i128::from(find::INFO_LEVEL_BOTH_DIRECTORY_INFO),
        ),
        (
            "smb1_query_basic_class",
            "fscc_basic_class",
            i128::from(info::query_level::BASIC_INFO),
        ),
        (
            "smb1_query_standard_class",
            "fscc_standard_class",
            i128::from(info::query_level::STANDARD_INFO),
        ),
    ] {
        assert_eq!(actual, number(&vectors, ours), "{ours}");
        assert_ne!(
            number(&vectors, ours),
            number(&vectors, theirs),
            "{ours}: an SMB2 class number would have reached the wire"
        );
    }
}
