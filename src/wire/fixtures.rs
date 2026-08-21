//! The wire layer asserted against the committed fixture corpus, offline.
//!
//! **For client-to-server messages the assertion is decode-then-re-encode, not
//! byte-identity against a fresh encode.** This crate departs from what the
//! capturing client sent in eleven ways, and one of them is the header's own
//! `Flags2`, so no request it builds of its own accord reproduces a captured
//! one byte for byte. What is asserted instead is that the committed frame
//! decodes to the fields it should and that re-encoding *those decoded fields*
//! reproduces the bytes exactly: the codec is pinned, the defaults are not.
//! Server-to-client frames have no such problem, and are re-encoded the same
//! way wherever this crate has an encoder for them.
//!
//! The captures are not templated for host and port either — the committed
//! frames carry the capture relay's own loopback address and ephemeral port
//! literally — which is one more reason a test comparing request bytes has to
//! work from the decoded frame rather than from a freshly built one.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

use super::header::{FLAGS2_KNOWS_EAS, SmbHeader, command};
use super::netbios;
use super::{Message, WireError, message};

/// The fixture corpus, as copied into this repository.
fn corpus() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// Reads one fixture and strips its NetBIOS header, returning both.
fn frame(relative: &str) -> (usize, Vec<u8>) {
    let bytes = fs::read(corpus().join(relative)).expect("fixture is readable");
    let header: [u8; netbios::HEADER_LEN] = bytes[..netbios::HEADER_LEN]
        .try_into()
        .expect("fixture carries a NetBIOS header");
    let (kind, length) = netbios::decode_header(header).expect("NetBIOS header decodes");
    assert_eq!(kind, netbios::MessageType::SessionMessage);
    assert_eq!(
        length,
        bytes.len() - netbios::HEADER_LEN,
        "{relative}: declared length and file size disagree"
    );
    (length, bytes[netbios::HEADER_LEN..].to_vec())
}

/// Reads one fixture as a parsed message.
fn parse(relative: &str) -> Message {
    let (_, body) = frame(relative);
    Message::parse(body).unwrap_or_else(|error| panic!("{relative}: {error}"))
}

/// Every fixture path, in sorted order.
fn every_fixture() -> Vec<String> {
    fn walk(root: &Path, prefix: &str, out: &mut Vec<String>) {
        let mut entries: Vec<_> = fs::read_dir(root)
            .expect("corpus directory is readable")
            .map(|entry| entry.expect("directory entry is readable").path())
            .collect();
        entries.sort();
        for path in entries {
            let name = path
                .file_name()
                .expect("entry has a name")
                .to_string_lossy();
            let relative = if prefix.is_empty() {
                name.to_string()
            } else {
                format!("{prefix}/{name}")
            };
            if path.is_dir() {
                walk(&path, &relative, out);
            } else if relative != "MANIFEST.sha256" {
                out.push(relative);
            }
        }
    }
    let mut out = Vec::new();
    walk(&corpus(), "", &mut out);
    out
}

/// Every committed frame, which is every fixture whose name ends in `.bin`.
fn every_frame() -> Vec<String> {
    every_fixture()
        .into_iter()
        .filter(|name| name.ends_with(".bin"))
        .collect()
}

/// The digest manifest guards the copy of the corpus into this repository: a
/// matching one is committed beside the corpus in the repository the fixtures
/// are captured in, and what says the two still agree is the two manifests
/// agreeing. This suite verifies its own fixtures against its own manifest,
/// which is what catches a fixture edited without it — in either direction, so
/// a fixture added without a manifest line fails here too.
#[test]
fn every_fixture_matches_the_manifest() {
    let raw = fs::read_to_string(corpus().join("MANIFEST.sha256")).expect("manifest is readable");
    let mut declared = BTreeMap::new();
    for line in raw.lines() {
        if line.starts_with('#') || line.trim().is_empty() {
            continue;
        }
        let (digest, path) = line
            .split_once("  ")
            .unwrap_or_else(|| panic!("manifest line is not sha256sum format: {line}"));
        declared.insert(path.to_owned(), digest.to_owned());
    }

    let present = every_fixture();
    assert_eq!(
        present.len(),
        declared.len(),
        "the corpus holds {} files and the manifest declares {}",
        present.len(),
        declared.len()
    );

    for relative in &present {
        let expected = declared
            .get(relative)
            .unwrap_or_else(|| panic!("{relative} is in the corpus and not in the manifest"));
        let bytes = fs::read(corpus().join(relative)).expect("fixture is readable");
        let digest = hex::encode(Sha256::digest(&bytes));
        assert_eq!(&digest, expected, "{relative} does not match its digest");
    }
}

/// The property that makes a parsing crate worth taking over hand-rolled byte
/// pushing: a plain derive round-trips the 32-byte header byte-identically
/// against every committed frame there is.
#[test]
fn the_header_derive_round_trips_every_committed_frame() {
    for relative in every_frame() {
        let (_, body) = frame(&relative);
        let parsed = Message::parse(body.clone()).unwrap_or_else(|e| panic!("{relative}: {e}"));
        let reencoded = message(parsed.header(), &[]).expect("header re-encodes");
        assert_eq!(
            reencoded.as_slice(),
            &body[..32],
            "{relative}: header did not round-trip"
        );
    }
}

/// Every committed frame carries the reference client's `Flags2` of `0xC803`,
/// which is this crate's value plus `SMB_FLAGS2_KNOWS_EAS`. That is the
/// departure that makes decode-then-re-encode the rule for every
/// client-to-server frame rather than for a list of exceptions.
#[test]
fn no_committed_request_carries_the_flags2_this_crate_sends() {
    for relative in every_frame() {
        let parsed = parse(&relative);
        assert_eq!(
            parsed.header().flags2,
            0xC803,
            "{relative}: unexpected Flags2"
        );
        assert_eq!(parsed.header().flags2 & FLAGS2_KNOWS_EAS, FLAGS2_KNOWS_EAS);
    }
    assert_eq!(super::header::FLAGS2_CLIENT, 0xC801);
    assert_eq!(super::header::FLAGS_CLIENT, 0x18);
}

/// Decodes a client-to-server frame and re-encodes the decoded fields, which
/// must reproduce the committed bytes exactly.
fn round_trip(relative: &str) {
    let (_, body) = frame(relative);
    let parsed = Message::parse(body.clone()).unwrap_or_else(|e| panic!("{relative}: {e}"));
    let encoded = encode_again(&parsed).unwrap_or_else(|e| panic!("{relative}: {e}"));
    let rebuilt = message(parsed.header(), &encoded).expect("message assembles");
    assert_eq!(
        rebuilt, body,
        "{relative}: did not re-encode to its own bytes"
    );

    let framed = super::frame(&rebuilt).expect("frame assembles");
    let original = fs::read(corpus().join(relative)).expect("fixture is readable");
    assert_eq!(framed, original, "{relative}: NetBIOS framing differs");
}

/// Decodes a message and encodes the decoded fields back to a command body.
fn encode_again(parsed: &Message) -> Result<Vec<u8>, WireError> {
    use super::file::{
        CloseRequest, CloseResponse, NtCreateAndxRequest, NtCreateAndxResponse, RenameRequest,
    };
    use super::io::{ReadAndxRequest, ReadAndxResponse, WriteAndxRequest, WriteAndxResponse};
    use super::negotiate::{NegotiateRequest, NegotiateResponse};
    use super::session::LogoffAndx;
    use super::transaction::{TransactionRequest, TransactionResponse};
    use super::tree::{TreeConnectAndxRequest, TreeConnectAndxResponse, TreeDisconnect};

    let request = parsed.header().flags & 0x80 == 0;
    match (parsed.header().command, request) {
        (command::NEGOTIATE, true) => NegotiateRequest::decode(parsed)?.encode_body(),
        (command::NEGOTIATE, false) => NegotiateResponse::decode(parsed)?.encode_body(),
        (command::TREE_CONNECT_ANDX, true) => TreeConnectAndxRequest::decode(parsed)?.encode_body(),
        (command::TREE_CONNECT_ANDX, false) => {
            TreeConnectAndxResponse::decode(parsed)?.encode_body()
        }
        (command::TREE_DISCONNECT, _) => TreeDisconnect::decode(parsed)?.encode_body(),
        (command::LOGOFF_ANDX, _) => LogoffAndx::decode(parsed)?.encode_body(),
        (command::TRANSACTION2 | command::TRANSACTION, true) => {
            TransactionRequest::decode(parsed)?.encode_body()
        }
        (command::TRANSACTION2 | command::TRANSACTION, false) => {
            TransactionResponse::decode(parsed)?.encode_body()
        }
        (command::NT_CREATE_ANDX, true) => NtCreateAndxRequest::decode(parsed)?.encode_body(),
        (command::NT_CREATE_ANDX, false) => NtCreateAndxResponse::decode(parsed)?.encode_body(),
        (command::CLOSE, true) => CloseRequest::decode(parsed)?.encode_body(),
        (command::CLOSE, false) => CloseResponse::decode(parsed)?.encode_body(),
        (command::RENAME, true) => RenameRequest::decode(parsed)?.encode_body(),
        (command::READ_ANDX, true) => ReadAndxRequest::decode(parsed)?.encode_body(),
        (command::READ_ANDX, false) => ReadAndxResponse::decode(parsed)?.encode_body(),
        (command::WRITE_ANDX, true) => WriteAndxRequest::decode(parsed)?.encode_body(),
        (command::WRITE_ANDX, false) => WriteAndxResponse::decode(parsed)?.encode_body(),
        (other, _) => panic!("no codec for command {other:#04x}"),
    }
}

/// The corpus sweep. Every committed frame that carries a command body decodes
/// through this crate's codec and re-encodes to the bytes it came from.
///
/// The frames that do not are the error responses, which carry no body: those
/// are asserted separately, since re-encoding a body that is not there proves
/// nothing.
#[test]
fn every_committed_frame_round_trips_through_its_codec() {
    let frames = every_frame();
    // Named so that a corpus that quietly loses frames fails here rather than
    // passing with less to prove.
    assert_eq!(frames.len(), 244, "the corpus changed size");

    let mut bodyless = Vec::new();
    for relative in frames {
        let parsed = parse(&relative);
        // Zero words alone does not make a frame bodyless. A negotiate
        // *request* carries none by definition, and `SMB_COM_CLOSE` and
        // `SMB_COM_TREE_DISCONNECT` answer with none when they succeed.
        let ordinary_zero = matches!(
            parsed.header().command,
            command::CLOSE | command::TREE_DISCONNECT | command::NEGOTIATE
        );
        if parsed.is_bodyless() && !ordinary_zero {
            bodyless.push(relative);
            continue;
        }
        round_trip(&relative);
    }
    assert_eq!(
        bodyless,
        [
            "capture-trans/0010-s2c-cmd25.bin",
            "capture-trans/0018-s2c-cmd25.bin",
            "capture-trans/0024-s2c-cmd25.bin",
            "capture-win-a/0008-s2c-cmd75.bin",
            "capture-win-a/0012-s2c-cmd32.bin",
            "capture-win-b/0008-s2c-cmd75.bin",
            "capture-win-frag/0008-s2c-cmd75.bin",
        ],
        "the set of frames carrying no command body changed"
    );
}

/// SMB1 usually answers a failed command with `WordCount = 0` and an empty byte
/// area rather than a zeroed version of that command's successful response. A
/// derive that reads `TREE_CONNECT_ANDX_RESPONSE`'s words unconditionally fails
/// on three of these.
#[test]
fn an_error_response_carries_no_words_for_most_commands() {
    use super::tree::TreeConnectAndxResponse;
    use crate::status::NtStatus;

    for (relative, status, expected_command) in [
        (
            "capture-win-a/0008-s2c-cmd75.bin",
            NtStatus::DUPLICATE_NAME,
            command::TREE_CONNECT_ANDX,
        ),
        (
            "capture-win-b/0008-s2c-cmd75.bin",
            NtStatus::DUPLICATE_NAME,
            command::TREE_CONNECT_ANDX,
        ),
        (
            "capture-win-frag/0008-s2c-cmd75.bin",
            NtStatus::DUPLICATE_NAME,
            command::TREE_CONNECT_ANDX,
        ),
        (
            "capture-win-a/0012-s2c-cmd32.bin",
            NtStatus::INSUFF_SERVER_RESOURCES,
            command::TRANSACTION2,
        ),
        (
            "capture-trans/0010-s2c-cmd25.bin",
            NtStatus::NOT_SUPPORTED,
            command::TRANSACTION,
        ),
        (
            "capture-trans/0018-s2c-cmd25.bin",
            NtStatus::NOT_SUPPORTED,
            command::TRANSACTION,
        ),
        (
            "capture-trans/0024-s2c-cmd25.bin",
            NtStatus::NOT_SUPPORTED,
            command::TRANSACTION,
        ),
    ] {
        let (length, _) = frame(relative);
        assert_eq!(length, 35, "{relative}: SMB message length");
        let parsed = parse(relative);
        assert_eq!(parsed.word_count(), 0, "{relative}");
        assert_eq!(parsed.byte_count(), 0, "{relative}");
        assert_eq!(parsed.header().status, status, "{relative}");
        assert!(parsed.is_bodyless(), "{relative}");
        assert_eq!(parsed.header().command, expected_command, "{relative}");
    }

    // The rule is named per command rather than derived from the status class,
    // and this is what a decoder built the wrong way runs into.
    assert!(matches!(
        TreeConnectAndxResponse::decode(&parse("capture-win-a/0008-s2c-cmd75.bin")),
        Err(WireError::NoResponseBody {
            command: command::TREE_CONNECT_ANDX,
            ..
        })
    ));
}

/// Five committed frames carry a non-zero `AndXOffset` beside
/// `AndXCommand = 0xFF`, and in every one the offset equals the SMB message
/// length exactly. A parser that seeks to it before checking the sentinel lands
/// precisely on the buffer boundary, so the bug surfaces as an empty read
/// rather than as an out-of-range seek that would be caught.
#[test]
fn a_non_zero_andx_offset_sits_beside_the_sentinel() {
    use super::andx::{AndX, NO_FURTHER_COMMAND};
    use super::read_words;

    let mut seen = Vec::new();
    for relative in every_frame() {
        let parsed = parse(&relative);
        let andx_command = matches!(
            parsed.header().command,
            command::READ_ANDX
                | command::WRITE_ANDX
                | command::LOGOFF_ANDX
                | command::TREE_CONNECT_ANDX
                | command::NT_CREATE_ANDX
        );
        if !andx_command || parsed.word_count() < 2 {
            continue;
        }
        let andx: AndX = read_words(&parsed.words()[..4]).expect("AndX prologue reads");
        assert_eq!(
            andx.command, NO_FURTHER_COMMAND,
            "{relative}: chains {:#04x}",
            andx.command
        );
        assert!(andx.refuse_chaining().is_ok());
        if andx.offset != 0 {
            let (length, _) = frame(&relative);
            assert_eq!(
                usize::from(andx.offset),
                length,
                "{relative}: AndXOffset is not the message length"
            );
            seen.push((relative, andx.offset));
        }
    }
    assert_eq!(
        seen,
        [
            ("capture-win-a/0010-s2c-cmd75.bin".to_owned(), 54),
            ("capture-win-b/0010-s2c-cmd75.bin".to_owned(), 54),
            ("capture-win-b/0016-s2c-cmd74.bin".to_owned(), 39),
            ("capture-win-frag/0010-s2c-cmd75.bin".to_owned(), 54),
            ("capture-win-frag/0072-s2c-cmd74.bin".to_owned(), 39),
        ]
    );
}

/// The negotiate exchange. The offer in the corpus is the reference's three
/// dialects; this crate offers one, which is what makes index validation a
/// separate step from decoding.
#[test]
fn negotiate_decodes_and_the_index_check_is_separate_from_it() {
    use super::negotiate::{NT_LM_0_12, NegotiateRequest, NegotiateResponse};

    let offered = NegotiateRequest::decode(&parse("capture/0001-c2s-cmd72.bin")).unwrap();
    assert_eq!(
        offered.dialects,
        ["NT LM 0.12", "NT LANMAN 1.0", "LANMAN1.0"]
    );
    assert_eq!(
        NegotiateRequest::single_dialect().dialects,
        [NT_LM_0_12.to_owned()]
    );

    let samba = NegotiateResponse::decode(&parse("capture/0002-s2c-cmd72.bin")).unwrap();
    assert_eq!(samba.words.dialect_index, 1);
    assert_eq!(samba.words.max_buffer_size, 16_644);
    assert_eq!(samba.words.capabilities, 0x8080_F3FD);
    assert_eq!(samba.words.max_mpx_count, 50);
    assert_eq!(samba.words.security_mode, 0x03);
    assert_eq!(samba.words.encryption_key_length, 0);
    assert_eq!(&samba.server_guid[..12], b"e33857d2f589");
    assert_eq!(samba.security_blob[0], 0x60);

    let windows = NegotiateResponse::decode(&parse("capture-win-a/0002-s2c-cmd72.bin")).unwrap();
    assert_eq!(windows.words.dialect_index, 0);
    assert_eq!(windows.words.max_buffer_size, 4_356);
    assert_eq!(windows.words.capabilities, 0x8001_E3FC);
    assert_eq!(windows.words.security_mode, 0x03);

    // Both servers answered the same 17-word body. Against the three-dialect
    // offer they disagree about the index, which is why validating by index
    // would pass on one family and fail on the other. Against this crate's
    // single-dialect offer only 0 is conforming.
    assert!(windows.accepted_offered_dialect().is_ok());
    assert!(matches!(
        samba.accepted_offered_dialect(),
        Err(WireError::UnsupportedDialectIndex(1))
    ));

    let mut refused = windows.clone();
    refused.words.dialect_index = 0xFFFF;
    assert!(matches!(
        refused.accepted_offered_dialect(),
        Err(WireError::NoCommonDialect)
    ));

    // The shape is keyed off `WordCount` alone.
    let mut short = parse("capture/0002-s2c-cmd72.bin");
    assert_eq!(short.word_count(), 17);
    short = parse("capture-win-a/0008-s2c-cmd75.bin");
    assert!(matches!(
        NegotiateResponse::decode(&short),
        Err(WireError::UnexpectedCommand { .. })
    ));
}

/// The TRANS2 request layout, and the padding that is pinned by these bytes
/// rather than reasoned about. The parameter block is aligned to two bytes and
/// not to four: a four-byte-aligned block would land on 68 rather than 66 and
/// move every offset after it.
#[test]
fn a_trans2_request_puts_its_parameter_block_on_sixty_six() {
    use super::find::{FindFirst2Params, FindNext2Params, SUBCOMMAND_FIND_FIRST2};
    use super::transaction::TransactionRequest;

    let parsed = parse("capture/0009-c2s-cmd32.bin");
    assert_eq!(parsed.word_count(), 15);
    assert_eq!(parsed.byte_area_offset(), 65);
    assert_eq!(parsed.byte_count(), 19);

    let request = TransactionRequest::decode(&parsed).unwrap();
    assert_eq!(request.command, command::TRANSACTION2);
    assert_eq!(request.setup, [SUBCOMMAND_FIND_FIRST2]);
    assert_eq!(request.parameters.len(), 18);
    assert_eq!(request.data, Vec::<u8>::new());
    assert_eq!(request.max_parameter_count, 1024);
    assert_eq!(request.max_data_count, 65_535);
    assert_eq!(request.max_setup_count, 0);
    assert_eq!(request.flags, 0);
    assert_eq!(request.timeout, 0);

    // The declared offsets, read straight out of the word block.
    assert_eq!(
        u16::from_le_bytes([parsed.words()[20], parsed.words()[21]]),
        66
    );
    assert_eq!(
        u16::from_le_bytes([parsed.words()[24], parsed.words()[25]]),
        84
    );

    let params = FindFirst2Params::decode(&request.parameters).unwrap();
    assert_eq!(params.search_attributes, 0x0016);
    assert_eq!(params.search_count, 100);
    assert_eq!(params.flags, 0x0002);
    assert_eq!(params.information_level, 0x0104);
    assert_eq!(params.pattern, "\\*");
    assert_eq!(params.encode().unwrap(), request.parameters);

    let next = TransactionRequest::decode(&parse("capture-frag/0012-c2s-cmd32.bin")).unwrap();
    let next = FindNext2Params::decode(&next.parameters).unwrap();
    assert_eq!(next.sid, 256);
    assert_eq!(next.search_count, 100);
    assert_eq!(next.information_level, 0x0104);
    assert_eq!(next.resume_key, 0);
    assert_eq!(next.flags, 0x0008);
    assert_eq!(next.pattern, "bigdir\\*");
}

/// The two `SMB_COM_TRANSACTION` shapes, which do not lay their byte areas out
/// the same way.
#[test]
fn a_named_transaction_and_a_pipe_transact_differ_in_the_byte_area() {
    use super::transaction::{
        NameEncoding, PIPE_LANMAN, TRANS_TRANSACT_NMPIPE, TransactionRequest,
    };

    let rap = parse("capture-trans/0009-c2s-cmd25.bin");
    assert_eq!(rap.word_count(), 16);
    assert_eq!(rap.byte_area_offset(), 67);
    assert_eq!(rap.byte_count(), 33);
    let rap = TransactionRequest::decode(&rap).unwrap();
    assert_eq!(rap.command, command::TRANSACTION);
    let name = rap.name.clone().expect("the RAP path names its pipe");
    assert_eq!(name.text, PIPE_LANMAN);
    // The reference's spelling, and the reason this frame was refused.
    assert_eq!(name.encoding, NameEncoding::Ascii);
    assert_eq!(rap.setup, [0, 0]);
    assert_eq!(rap.max_parameter_count, 1024);
    assert_eq!(rap.parameters.len(), 19);
    assert_eq!(&rap.parameters[..2], [0, 0]);
    assert_eq!(&rap.parameters[2..8], b"WrLeh\0");
    assert_eq!(&rap.parameters[8..15], b"B13BWz\0");
    assert!(rap.data.is_empty());

    let pipe = parse("capture-trans/0017-c2s-cmd25.bin");
    assert_eq!(pipe.byte_count(), 116);
    let pipe = TransactionRequest::decode(&pipe).unwrap();
    assert_eq!(pipe.name, None);
    assert_eq!(pipe.setup, [TRANS_TRANSACT_NMPIPE, 0xB0D0]);
    assert_eq!(pipe.max_parameter_count, 0);
    assert!(pipe.parameters.is_empty());
    assert_eq!(pipe.data.len(), 116);
    // The DCE/RPC bind, at the very first byte of the byte area.
    assert_eq!(&pipe.data[..4], [0x05, 0x00, 0x0B, 0x03]);
}

/// A fragmented TRANS2 reply, which is what reassembly is built over. The
/// declared totals and displacements are what the connection task needs, and
/// they are decoded here rather than inferred.
#[test]
fn a_fragmented_reply_declares_totals_and_displacements() {
    use super::find::FindReply;
    use super::transaction::TransactionResponse;

    let first = TransactionResponse::decode(&parse("capture-frag/0010-s2c-cmd32.bin")).unwrap();
    assert_eq!(first.total_parameter_count, 10);
    assert_eq!(first.total_data_count, 17_836);
    assert_eq!(first.parameters.len(), 10);
    assert_eq!(first.data.len(), 16_572);
    assert_eq!(first.data_displacement, 0);
    assert_eq!(first.parameter_offset, 56);
    assert_eq!(first.data_offset, 68);

    let reply = FindReply::decode_first(&first.parameters).unwrap();
    assert_eq!(reply.sid, Some(256));
    assert_eq!(reply.search_count, 100);
    assert_eq!(reply.end_of_search, 0);
    assert_eq!(reply.last_name_offset, 17_656);

    let second = TransactionResponse::decode(&parse("capture-frag/0011-s2c-cmd32.bin")).unwrap();
    assert_eq!(second.total_data_count, 17_836);
    assert_eq!(second.parameters, Vec::<u8>::new());
    assert_eq!(second.data.len(), 1_264);
    assert_eq!(second.data_displacement, 16_572);
    assert_eq!(
        second.data_displacement as usize + second.data.len(),
        usize::from(second.total_data_count)
    );

    // The trailing entry of the first message begins 176 bytes before that
    // message's data ends and continues in the second, which is why the chain
    // is walked over the reassembled buffer and never over one message.
    assert!(super::find::walk_entries(&first.data, 100).is_err());
}

/// Both directory-chain terminators, each on the server whose convention it is.
#[test]
fn both_chain_terminators_are_honoured() {
    use super::find::{FindReply, walk_entries};
    use super::transaction::TransactionResponse;

    // Samba: the last entry points just past itself, landing exactly on the
    // `DataCount` boundary. There is no zero terminator anywhere in the chain.
    let samba = TransactionResponse::decode(&parse("capture/0010-s2c-cmd32.bin")).unwrap();
    let reply = FindReply::decode_first(&samba.parameters).unwrap();
    assert_eq!(reply.sid, Some(0xFFFF));
    assert_eq!(reply.search_count, 6);
    assert_eq!(reply.end_of_search, 1);
    assert_eq!(reply.last_name_offset, 552);
    assert_eq!(samba.data.len(), 664);

    let entries = walk_entries(&samba.data, reply.search_count).unwrap();
    let names: Vec<&str> = entries.iter().map(|e| e.file_name.as_str()).collect();
    assert_eq!(
        names,
        [
            ".",
            "..",
            "alpha.txt",
            "gamma-longer-name.dat",
            "subdir",
            "beta.bin"
        ]
    );
    // The terminal entry begins at 552 and measures 112, which lands on 664.
    assert_eq!(
        u32::from_le_bytes(samba.data[552..556].try_into().unwrap()),
        112
    );
    assert_eq!(552 + 112, samba.data.len());

    // Windows: a zero `NextEntryOffset`, and six bytes of trailing padding the
    // walk never reaches.
    let windows = TransactionResponse::decode(&parse("capture-win-b/0012-s2c-cmd32.bin")).unwrap();
    let reply = FindReply::decode_first(&windows.parameters).unwrap();
    assert_eq!(reply.search_count, 7);
    assert_eq!(reply.end_of_search, 1);
    assert_eq!(windows.data.len(), 788);

    let entries = walk_entries(&windows.data, reply.search_count).unwrap();
    assert_eq!(entries.len(), 7);
    assert_eq!(entries[6].file_name, "subdir");
    assert_eq!(entries[5].short_name, "GAMMA-~1.DAT");
    assert_eq!(
        u32::from_le_bytes(windows.data[676..680].try_into().unwrap()),
        0
    );
    assert_eq!(676 + 94 + 12 + 6, windows.data.len());
}

/// One server is not internally consistent about its own padding, so an entry's
/// size is never computed from an assumed stride. The `.` entry has a 96-byte
/// body under a `NextEntryOffset` of 100 in one capture and of 96 in another,
/// from the same server for identical content.
#[test]
fn the_same_server_pads_identical_entries_differently() {
    use super::transaction::TransactionResponse;

    let b = TransactionResponse::decode(&parse("capture-win-b/0012-s2c-cmd32.bin")).unwrap();
    let frag = TransactionResponse::decode(&parse("capture-win-frag/0012-s2c-cmd32.bin")).unwrap();

    // Both are the `.` entry: 94 fixed bytes and a two-byte name.
    assert_eq!(u32::from_le_bytes(b.data[60..64].try_into().unwrap()), 2);
    assert_eq!(u32::from_le_bytes(frag.data[60..64].try_into().unwrap()), 2);
    assert_eq!(u32::from_le_bytes(b.data[0..4].try_into().unwrap()), 100);
    assert_eq!(u32::from_le_bytes(frag.data[0..4].try_into().unwrap()), 96);
}

/// The reason `ByteCount` must never be used as a length, in committed bytes.
///
/// A 130,048-byte read reply carries `ByteCount = 64513`, and the write that
/// put those bytes there carries `ByteCount = 64512` beside
/// `DataLengthHigh = 1`. A derive written the obvious way yields 64,513 of
/// 130,048 bytes: a silent short read.
#[test]
fn a_large_transfer_is_not_bounded_by_byte_count() {
    use super::io::{ReadAndxRequest, ReadAndxResponse, WriteAndxRequest, WriteAndxResponse};

    let (length, _) = frame("capture-large/0018-s2c-cmd2e.bin");
    assert_eq!(length, 130_108);
    let reply = parse("capture-large/0018-s2c-cmd2e.bin");
    assert_eq!(reply.byte_count(), 64_513);
    let reply = ReadAndxResponse::decode(&reply).unwrap();
    assert_eq!(reply.data.len(), 130_048);
    assert_eq!(reply.data_offset, 60);
    assert_eq!(reply.available, 0xFFFF);

    let ask = ReadAndxRequest::decode(&parse("capture-large/0015-c2s-cmd2e.bin")).unwrap();
    assert_eq!(ask.max_count, 130_048);
    assert_eq!(ask.offset, 0);

    let (length, _) = frame("capture-large/0027-c2s-cmd2f.bin");
    assert_eq!(length, 130_111);
    let write = parse("capture-large/0027-c2s-cmd2f.bin");
    assert_eq!(write.byte_count(), 64_512);
    let write = WriteAndxRequest::decode(&write).unwrap();
    assert_eq!(write.data.len(), 130_048);

    let ack = WriteAndxResponse::decode(&parse("capture-large/0030-s2c-cmd2f.bin")).unwrap();
    assert_eq!(ack.count, 130_048);

    // And the frame that carries it needs the seventeenth length bit: a 16-bit
    // read of the same NetBIOS header gives 64,572 and 64,575.
    let raw = fs::read(corpus().join("capture-large/0018-s2c-cmd2e.bin")).unwrap();
    assert_eq!(raw[1] & 0x01, 1);
    assert_eq!(raw[1] & 0xFE, 0);
    assert_eq!(u16::from_be_bytes([raw[2], raw[3]]), 64_572);
}

/// The negotiated buffer does not bound a capability-bearing transfer: the
/// 130,108-byte reply above arrived on a connection that negotiated 16,644.
#[test]
fn a_large_read_arrives_on_a_small_negotiated_buffer() {
    use super::negotiate::NegotiateResponse;

    let negotiated = NegotiateResponse::decode(&parse("capture-large/0002-s2c-cmd72.bin")).unwrap();
    assert_eq!(negotiated.words.max_buffer_size, 16_644);
    // `CAP_LARGE_READX` (0x00004000) and `CAP_LARGE_WRITEX` (0x00008000).
    assert_eq!(negotiated.words.capabilities & 0x0000_C000, 0x0000_C000);
}

/// The three name-alignment sites, on the frames that carry them. The
/// tree connect's path is aligned by a declared one-byte password rather than
/// by a pad, and `NT_CREATE_ANDX`'s name by a pad.
#[test]
fn the_name_alignment_sites_land_their_names_on_even_offsets() {
    use super::file::NtCreateAndxRequest;
    use super::tree::TreeConnectAndxRequest;

    let connect = parse("capture/0007-c2s-cmd75.bin");
    assert_eq!(connect.byte_area_offset(), 43);
    let connect = TreeConnectAndxRequest::decode(&connect).unwrap();
    assert_eq!(connect.password, [0]);
    assert_eq!(connect.path, "\\\\127.0.0.1\\TESTSHARE");
    assert_eq!(connect.service, "A:");

    // The IPC$ tree connect carries the relay's own port in the path, which is
    // why a test comparing request bytes has to work from the decoded frame.
    let ipc = TreeConnectAndxRequest::decode(&parse("capture-win-a/0007-c2s-cmd75.bin")).unwrap();
    assert_eq!(ipc.path, "\\\\127.0.0.1:10451\\IPC$");
    assert_eq!(ipc.service, "IPC");

    let create = parse("capture/0015-c2s-cmda2.bin");
    assert_eq!(create.byte_area_offset(), 83);
    assert_eq!(create.byte_area()[0], 0, "the pad byte before the name");
    let create = NtCreateAndxRequest::decode(&create).unwrap();
    assert_eq!(create.name, "alpha.txt");
    // The reference's values, both of which this crate departs from.
    assert_eq!(create.desired_access, 0x8010_0000);
    assert_eq!(create.share_access, 0x3);
    assert_eq!(create.create_disposition, 1);
    assert_eq!(create.impersonation_level, 2);
}

/// The tree-connect response, which is where `AndXOffset` beside the sentinel
/// first shows up, and where a three-word body is the ordinary shape.
#[test]
fn a_tree_connect_response_decodes_its_service_and_filesystem() {
    use super::tree::TreeConnectAndxResponse;

    for relative in [
        "capture/0008-s2c-cmd75.bin",
        "capture-win-b/0010-s2c-cmd75.bin",
    ] {
        let parsed = parse(relative);
        assert_eq!(parsed.word_count(), 3, "{relative}");
        let response = TreeConnectAndxResponse::decode(&parsed).unwrap();
        assert_eq!(response.optional_support, 1, "{relative}");
        assert_eq!(response.service, "A:", "{relative}");
        assert_eq!(response.native_file_system, "NTFS", "{relative}");
    }
}

/// Windows pages a large listing with `FIND_NEXT2` because the capturing client
/// asked for `MaxDataCount = 4000`; Samba fragments the same listing across
/// messages. A codec that handles only one of the two is incomplete against
/// both, and both are in the corpus.
#[test]
fn the_corpus_carries_both_ways_a_large_listing_arrives() {
    use super::transaction::TransactionRequest;

    let windows =
        TransactionRequest::decode(&parse("capture-win-frag/0011-c2s-cmd32.bin")).unwrap();
    assert_eq!(windows.max_data_count, 4_000);
    assert_eq!(windows.max_parameter_count, 1024);

    let samba = TransactionRequest::decode(&parse("capture-frag/0009-c2s-cmd32.bin")).unwrap();
    assert_eq!(samba.max_data_count, 65_535);

    // The sum the reference asks for overshoots the measured Windows ceiling by
    // 35 bytes, which is what makes `capture-win-a/0012` the
    // `STATUS_INSUFF_SERVER_RESOURCES` frame.
    let overshooting =
        TransactionRequest::decode(&parse("capture-win-a/0011-c2s-cmd32.bin")).unwrap();
    assert_eq!(
        u32::from(overshooting.max_parameter_count) + u32::from(overshooting.max_data_count),
        66_559
    );
    assert!(matches!(
        overshooting.check_limits(65_535),
        Err(WireError::FieldTooLong { length: 66_559, .. })
    ));
}

/// The same RAP request spelled the way the specification requires, and
/// answered.
///
/// `SMB_COM_TRANSACTION`'s `Name` is a fourth name-alignment site and the one
/// the reference library gets wrong: it sets `SMB_FLAGS2_UNICODE` and then
/// writes 8-bit ASCII at an odd offset, and Samba — reading those bytes as the
/// UTF-16 they claim to be — refuses the frame. Both spellings are in the
/// corpus, carrying the same name and the same 19 parameter bytes, and the only
/// difference between them is how the name is written and where every offset
/// after it therefore lands.
#[test]
fn the_two_spellings_of_a_transaction_name_differ_only_in_the_name() {
    use super::transaction::{NameEncoding, PIPE_LANMAN, TransactionRequest, TransactionResponse};
    use crate::status::NtStatus;

    let refused = TransactionRequest::decode(&parse("capture-trans/0009-c2s-cmd25.bin")).unwrap();
    let answered = TransactionRequest::decode(&parse("capture-rap/0009-c2s-cmd25.bin")).unwrap();

    let refused_name = refused.name.clone().unwrap();
    let answered_name = answered.name.clone().unwrap();
    assert_eq!(refused_name.text, PIPE_LANMAN);
    assert_eq!(answered_name.text, PIPE_LANMAN);
    assert_eq!(refused_name.encoding, NameEncoding::Ascii);
    assert_eq!(answered_name.encoding, NameEncoding::Unicode);
    assert_eq!(refused.parameters, answered.parameters);
    assert_eq!(refused.setup, answered.setup);

    // The ASCII name sits at 67 unaligned and takes 13 bytes; the UTF-16 one is
    // padded onto 68 and takes 26, which moves both offsets by 14.
    let frame_refused = parse("capture-trans/0009-c2s-cmd25.bin");
    let frame_answered = parse("capture-rap/0009-c2s-cmd25.bin");
    assert_eq!(frame_refused.byte_area_offset(), 67);
    assert_eq!(frame_answered.byte_area_offset(), 67);
    assert_eq!(frame_refused.byte_count(), 33);
    assert_eq!(frame_answered.byte_count(), 47);
    assert_eq!(frame_answered.byte_area()[0], 0, "the pad before the name");
    assert_eq!(&frame_answered.byte_area()[1..3], [0x5C, 0x00]);
    let words = frame_answered.words();
    assert_eq!(u16::from_le_bytes([words[20], words[21]]), 94);
    assert_eq!(u16::from_le_bytes([words[24], words[25]]), 114);

    // Both carry the flag whose meaning the reference contradicts.
    assert_eq!(frame_refused.header().flags2, 0xC803);
    assert_eq!(frame_answered.header().flags2, 0xC803);

    // What this crate builds is the answered spelling, and it reproduces that
    // frame's own offsets.
    let built = TransactionRequest::rap(answered.parameters.clone(), Vec::new());
    assert_eq!(built.name.unwrap().encoding, NameEncoding::Unicode);

    // The refusal, and the reply the corrected request earned. The corpus held
    // no successful `SMB_COM_TRANSACTION` reply before this one.
    assert_eq!(
        parse("capture-trans/0010-s2c-cmd25.bin").header().status,
        NtStatus::NOT_SUPPORTED
    );
    let reply = parse("capture-rap/0010-s2c-cmd25.bin");
    assert_eq!(reply.header().status, NtStatus::SUCCESS);
    assert_eq!(reply.word_count(), 10);
    let reply = TransactionResponse::decode(&reply).unwrap();
    assert_eq!(reply.total_parameter_count, 8);
    assert_eq!(reply.total_data_count, 68);
    assert_eq!(reply.parameter_offset, 56);
    assert_eq!(reply.data_offset, 64);
    // RAP status `NERR_Success`, converter 0, 2 entries returned of 2 available.
    assert_eq!(reply.parameters, [0, 0, 0, 0, 2, 0, 2, 0]);
}

/// The fallback the embedded device forces, captured against a container that
/// refuses `SMB_COM_TRANSACTION`: the transact attempt is answered
/// `STATUS_NOT_SUPPORTED`, and the DCE/RPC exchange then rides on `WRITE_ANDX`
/// and `READ_ANDX` instead. A client that implements only the transact mode
/// enumerates nothing there.
#[test]
fn a_refused_transaction_is_followed_by_the_write_read_exchange() {
    use super::io::{ReadAndxRequest, ReadAndxResponse, WriteAndxRequest, WriteAndxResponse};
    use super::transaction::{TRANS_TRANSACT_NMPIPE, TransactionRequest};
    use crate::status::NtStatus;

    let refused = parse("capture-trans/0023-c2s-cmd25.bin");
    let refused_request = TransactionRequest::decode(&refused).unwrap();
    assert_eq!(refused_request.setup[0], TRANS_TRANSACT_NMPIPE);
    assert_eq!(
        parse("capture-trans/0024-s2c-cmd25.bin").header().status,
        NtStatus::NOT_SUPPORTED
    );

    // The same 108 bytes, written to the same pipe handle instead.
    let write = WriteAndxRequest::decode(&parse("capture-trans/0025-c2s-cmd2f.bin")).unwrap();
    assert_eq!(write.fid, 0xB0D0);
    assert_eq!(write.offset, 208);
    assert_eq!(write.data, refused_request.data);
    assert_eq!(write.data.len(), 108);

    let ack = WriteAndxResponse::decode(&parse("capture-trans/0026-s2c-cmd2f.bin")).unwrap();
    assert_eq!(ack.count, 108);

    let read = ReadAndxRequest::decode(&parse("capture-trans/0027-c2s-cmd2e.bin")).unwrap();
    assert_eq!(read.fid, 0xB0D0);
    assert_eq!(read.offset, 316);

    let response = ReadAndxResponse::decode(&parse("capture-trans/0028-s2c-cmd2e.bin")).unwrap();
    assert_eq!(response.data.len(), 228);
    // A DCE/RPC response PDU: version 5.0, packet type 2, and both fragment
    // flags set on a single-PDU reply.
    assert_eq!(&response.data[..4], [0x05, 0x00, 0x02, 0x03]);
}

/// A keep-alive is consumed and discarded, and no other message type is
/// tolerated. No capture holds one — the relay logged nothing but session
/// messages — so this asserts against the framing rule rather than against
/// bytes.
#[test]
fn every_committed_frame_is_a_session_message() {
    for relative in every_frame() {
        let raw = fs::read(corpus().join(&relative)).unwrap();
        assert_eq!(raw[0], netbios::TYPE_SESSION_MESSAGE, "{relative}");
    }
}

/// A header this crate builds itself, checked against the constants rather than
/// against a capture, since no captured request carries them.
#[test]
fn a_request_header_carries_this_crates_flag_words() {
    let header = SmbHeader::request(command::NEGOTIATE);
    let encoded = message(&header, &[]).unwrap();
    assert_eq!(&encoded[..4], b"\xffSMB");
    assert_eq!(encoded[4], command::NEGOTIATE);
    assert_eq!(encoded[9], 0x18);
    assert_eq!(u16::from_le_bytes([encoded[10], encoded[11]]), 0xC801);
    assert_eq!(encoded.len(), 32);
}
