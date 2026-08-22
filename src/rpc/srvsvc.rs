//! `srvsvc`'s `NetrShareEnum` at information level 1, marshalled in NDR32.
//!
//! Level 1 is what carries a share's name, its type and its comment, which are
//! the three [`super::Share`] hands back. The reference library decodes all
//! three and returns only the name; here the comment is kept, because it is
//! what a user browsing shares actually reads.

use super::ndr::{NdrError, Reader, Writer};
use super::{Share, ShareKind};

/// `4b324fc8-1670-01d3-1278-5a47bf6ee188`, in the byte order a bind carries it.
pub const INTERFACE: [u8; 16] = [
    0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
];

/// The interface version the bind asks for: 3.0.
pub const INTERFACE_VERSION: u32 = 3;

/// `NetrShareEnum`.
pub const OPNUM: u16 = 15;

/// The information level asked for, on this path and on the RAP one alike.
const LEVEL: u32 = 1;

/// `PreferedMaximumLength`, the "no limit of my own" spelling.
///
/// The value the reference sends and every capture carries. **Bounding it was
/// tried and does not work**: Samba 4.23.8 returns the whole share list whatever
/// this field says — measured at 64 KiB and again at 4 KiB against a container
/// with 2,000 shares, both answered in one reply of several hundred kilobytes.
/// A client therefore cannot use this field to keep a reply small, so the
/// assembler in [`super::pdu`] carries that bound instead, where it does not
/// rest on a server's cooperation.
///
/// The paging loop below is still reached — by a server that pages of its own
/// accord, which is what `ERROR_MORE_DATA` and the resume handle are for.
const NO_PREFERRED_MAXIMUM: u32 = 0xFFFF_FFFF;

/// A referent id for a pointer this crate sends.
///
/// The value identifies a pointer within one stub and means nothing outside
/// it; all a server may do with it is tell two pointers apart. These are the
/// values the reference sends and the ones every request in the corpus carries.
const SERVER_NAME_REFERENT: u32 = 0x0002_0000;
const CONTAINER_REFERENT: u32 = 0x0002_0004;
const RESUME_HANDLE_REFERENT: u32 = 0x0002_0008;

/// `WERR_OK`.
const WERR_OK: u32 = 0;

/// `ERROR_MORE_DATA`, which srvsvc returns together with a resume handle when
/// the share list did not fit the reply.
///
/// This is not RAP's `ERROR_MORE_DATA` despite the shared name and the shared
/// value. There, it says RAP cannot produce the list and the client falls
/// through to this path; here there is nothing further to fall through to, so
/// it is a loop instead (see [`super::Ipc::list_shares`]).
pub const ERROR_MORE_DATA: u32 = 234;

/// What a `NetrShareEnum` reply can be that stops it decoding.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SrvsvcError {
    /// A field of the stub could not be read.
    #[error("NetrShareEnum reply: {0}")]
    Ndr(#[from] NdrError),

    /// The reply came back at an information level other than the one asked
    /// for, so the container it carries is not the one this crate decodes.
    #[error("NetrShareEnum reply is at information level {0}, not 1")]
    Level(u32),

    /// The reply's two level fields disagree with each other.
    #[error("NetrShareEnum reply declares level {outer} outside its container and {inner} inside")]
    LevelMismatch {
        /// The level beside the container.
        outer: u32,
        /// The level inside it.
        inner: u32,
    },

    /// The array's own conformance count is below the entry count beside it.
    ///
    /// Two statements about one array, and a reply that disagrees with itself
    /// about how many entries it sent is refused rather than decoded to
    /// whichever half is believed.
    #[error("NetrShareEnum reply reads {entries} entries out of an array of at most {maximum}")]
    ArrayTooSmall {
        /// `EntriesRead`.
        entries: u32,
        /// The array's conformance count.
        maximum: u32,
    },

    /// The reply says the server holds fewer shares in total than it just
    /// returned.
    #[error("NetrShareEnum reply returns {entries} entries of a declared total of {total}")]
    TotalBelowEntries {
        /// `EntriesRead`.
        entries: u32,
        /// `TotalEntries`.
        total: u32,
    },

    /// The call failed, and this is the code it failed with.
    #[error("NetrShareEnum failed: {0:#010x}")]
    Failed(u32),
}

/// The request stub for one round of the enumeration.
///
/// `server` is the server component of the UNC path the caller named, and
/// travels as the UNC form of it. `resume` is zero on the first round and
/// whatever the previous reply returned on every later one.
pub fn request(server: &str, resume: u32) -> Vec<u8> {
    let mut stub = Writer::new();
    // A top-level `[in]` pointer's target follows its referent id immediately,
    // rather than being deferred behind the parameters after it.
    stub.u32(SERVER_NAME_REFERENT);
    stub.conformant_varying_string(&unc(server));
    stub.u32(LEVEL);
    // SHARE_ENUM_STRUCT: the level again, then the union switched on it.
    stub.u32(LEVEL);
    stub.u32(CONTAINER_REFERENT);
    // The container, which on the way in is empty: no entries and no buffer.
    stub.u32(0);
    stub.u32(0);
    stub.u32(NO_PREFERRED_MAXIMUM);
    stub.u32(RESUME_HANDLE_REFERENT);
    stub.u32(resume);
    stub.finish()
}

/// One reply to `NetrShareEnum`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page {
    /// The shares this round returned.
    pub shares: Vec<Share>,
    /// How many shares the server says it has in total.
    pub total: u32,
    /// The handle to re-issue the call with, where the enumeration continues.
    pub resume: u32,
    /// Whether the server says there is more to come.
    pub more: bool,
}

/// Decodes one reply's stub.
///
/// The stub is the whole assembled response and never one PDU of it: the walk
/// below runs off the end of anything shorter, which is the point — a decoder
/// handed a first fragment fails here rather than returning the shares that
/// happened to fit in it.
pub fn response(stub: &[u8]) -> Result<Page, SrvsvcError> {
    let mut reader = Reader::new(stub);

    let outer = reader.u32("Level")?;
    if outer != LEVEL {
        return Err(SrvsvcError::Level(outer));
    }
    let inner = reader.u32("InfoStruct.Level")?;
    if inner != outer {
        return Err(SrvsvcError::LevelMismatch { outer, inner });
    }

    let mut shares = Vec::new();
    let mut entries = 0;
    if !reader.is_null_pointer("ShareInfo1 container")? {
        entries = reader.u32("EntriesRead")?;
        if !reader.is_null_pointer("container Buffer")? {
            shares = share_info_1_array(&mut reader, entries)?;
        }
    }

    let total = reader.u32("TotalEntries")?;
    if total < entries {
        return Err(SrvsvcError::TotalBelowEntries { entries, total });
    }
    let resume = if reader.is_null_pointer("ResumeHandle")? {
        0
    } else {
        reader.u32("ResumeHandle")?
    };
    let code = reader.u32("return value")?;

    match code {
        WERR_OK => Ok(Page {
            shares,
            total,
            resume,
            more: false,
        }),
        ERROR_MORE_DATA => Ok(Page {
            shares,
            total,
            resume,
            more: true,
        }),
        other => Err(SrvsvcError::Failed(other)),
    }
}

/// Walks an array of `SHARE_INFO_1`.
///
/// NDR puts every structure of the array first and every string they point at
/// after all of them, in the order the pointers were met — so the walk is two
/// passes over the same entries and not one.
fn share_info_1_array(reader: &mut Reader<'_>, entries: u32) -> Result<Vec<Share>, SrvsvcError> {
    let maximum = reader.u32("array conformance")?;
    if entries > maximum {
        return Err(SrvsvcError::ArrayTooSmall { entries, maximum });
    }
    // `entries` is a server-supplied count, so nothing is reserved from it: the
    // vector grows as the stub is walked and the stub is what runs out first.
    let mut structures = Vec::new();
    for _ in 0..entries {
        let named = !reader.is_null_pointer("share netname pointer")?;
        let kind = ShareKind::from_srvsvc(reader.u32("share type")?);
        let commented = !reader.is_null_pointer("share remark pointer")?;
        structures.push((named, kind, commented));
    }

    let mut shares = Vec::with_capacity(structures.len());
    for (named, kind, commented) in structures {
        let name = if named {
            reader.conformant_varying_string("share netname")?
        } else {
            String::new()
        };
        let comment = if commented {
            reader.conformant_varying_string("share remark")?
        } else {
            String::new()
        };
        shares.push(Share {
            name,
            kind,
            comment,
        });
    }
    Ok(shares)
}

/// The UNC form of a server name, which is what `ServerName` carries.
fn unc(server: &str) -> String {
    match server.strip_prefix('\\') {
        Some(rest) => format!("\\\\{}", rest.trim_start_matches('\\')),
        None => format!("\\\\{server}"),
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::rpc::ShareService;
    use crate::rpc::tests::{read_payload, stub, transaction_payload};

    /// Windows 11 24H2 answering `NetrShareEnum` over `SMB_COM_TRANSACTION`.
    ///
    /// This is a **captured** reply and not the synthesised one, which the
    /// design record was written before it existed: four shares, three of them
    /// administrative, and the two flag bits set on three different base types.
    #[test]
    fn windows_four_shares_decode_with_their_kinds_and_comments() {
        for capture in [
            "capture-win-rap/0020-s2c-cmd25.bin",
            "capture-win-nmpipe/0014-s2c-cmd25.bin",
        ] {
            let page = response(&stub(&transaction_payload(capture))).unwrap();
            assert_eq!(page.total, 4);
            assert_eq!(page.resume, 0);
            assert!(!page.more, "{capture} ends the enumeration");

            let named: Vec<_> = page
                .shares
                .iter()
                .map(|share| {
                    (
                        share.name.as_str(),
                        share.kind.service,
                        share.kind.special,
                        share.comment.as_str(),
                    )
                })
                .collect();
            assert_eq!(
                named,
                [
                    ("ADMIN$", ShareService::Disk, true, "Remote Admin"),
                    ("C$", ShareService::Disk, true, "Default share"),
                    ("IPC$", ShareService::Ipc, true, "Remote IPC"),
                    ("testshare", ShareService::Disk, false, ""),
                ],
                "{capture}"
            );
        }
    }

    /// The Samba container answering the same call, over both transports: the
    /// transact mode and the write/read fallback the reference is forced onto.
    ///
    /// Its referent ids run from `0x0002000c` where Windows' run from
    /// `0x00020000`, which is why nothing here looks one up.
    #[test]
    fn the_container_answers_the_same_call_over_both_transports() {
        let over_transact = response(&stub(&transaction_payload(
            "capture-nmpipe/0014-s2c-cmd25.bin",
        )))
        .unwrap();
        let over_write_read =
            response(&stub(&read_payload("capture-trans/0028-s2c-cmd2e.bin"))).unwrap();
        assert_eq!(over_transact, over_write_read);

        assert_eq!(over_transact.total, 2);
        assert!(!over_transact.more);
        assert_eq!(over_transact.shares[0].name, "testshare");
        assert_eq!(over_transact.shares[0].kind.service, ShareService::Disk);
        assert_eq!(over_transact.shares[0].comment, "");
        assert_eq!(over_transact.shares[1].name, "IPC$");
        assert_eq!(over_transact.shares[1].kind.service, ShareService::Ipc);
        assert!(over_transact.shares[1].kind.special);
        assert_eq!(
            over_transact.shares[1].comment,
            "IPC Service (Samba 4.23.8)"
        );
    }

    /// The synthesised fixture, which carries a third server's shape of the
    /// exchange — the one the container cannot produce.
    #[test]
    fn the_synthesised_fixture_decodes_to_its_three_shares() {
        let page = response(&stub(&read_payload(
            "srvsvc-synthesised/synth-0008-s2c-cmd2e.bin",
        )))
        .unwrap();
        assert_eq!(page.total, 3);
        assert_eq!(page.resume, 0);
        assert!(!page.more);
        assert_eq!(
            page.shares
                .iter()
                .map(|share| (share.name.as_str(), share.comment.as_str()))
                .collect::<Vec<_>>(),
            [
                ("SYNTH-VOL01", "Synthesised fixture share number 01"),
                ("SYNTH-DISK01", "Synthesised fixture share number 02"),
                ("IPC$", "Synthesised fixture IPC$ share remark"),
            ]
        );
        assert_eq!(page.shares[2].kind.service, ShareService::Ipc);
        assert!(page.shares[2].kind.special);
    }

    /// The request stub, byte for byte against three captured ones.
    ///
    /// Nothing in this stub is a departure from what the reference sends: the
    /// referent ids, the level, the empty container and the
    /// `PreferedMaximumLength` of `0xFFFFFFFF` are all its values, and this is
    /// what says so.
    #[test]
    fn the_request_stub_matches_every_captured_one() {
        for (capture, server) in [
            ("capture-win-rap/0019-c2s-cmd25.bin", "127.0.0.1"),
            ("capture-nmpipe/0013-c2s-cmd25.bin", "127.0.0.1:10458"),
        ] {
            assert_eq!(
                request(server, 0),
                stub(&transaction_payload(capture)),
                "{capture}"
            );
        }
        assert_eq!(
            request("127.0.0.1:10447", 0),
            stub(&read_payload_of_request(
                "srvsvc-synthesised/synth-0005-c2s-cmd2f.bin"
            ))
        );
    }

    /// The write side of the synthesised exchange carries its PDU on a
    /// `WRITE_ANDX` rather than a `READ_ANDX`.
    fn read_payload_of_request(relative: &str) -> Vec<u8> {
        crate::wire::io::WriteAndxRequest::decode(&crate::rpc::tests::fixture(relative))
            .unwrap()
            .data
    }

    /// A server name already in UNC form is not doubled, and a bare one is
    /// prefixed.
    #[test]
    fn the_server_name_reaches_the_wire_in_unc_form_however_it_arrives() {
        let expected = request("127.0.0.1", 0);
        assert_eq!(request("\\\\127.0.0.1", 0), expected);
        assert_eq!(request("\\127.0.0.1", 0), expected);
    }

    /// The resume handle is what a second round carries, and it is the only
    /// thing that changes between rounds.
    #[test]
    fn a_later_round_differs_from_the_first_in_the_resume_handle_alone() {
        let first = request("server", 0);
        let second = request("server", 0x1234_5678);
        assert_eq!(first.len(), second.len());
        assert_eq!(first[..first.len() - 4], second[..second.len() - 4]);
        assert_eq!(
            &second[second.len() - 4..],
            &0x1234_5678u32.to_le_bytes()[..]
        );
    }

    /// `ERROR_MORE_DATA` and a resume handle are a page, not a failure — and
    /// the shares that arrived with it are kept.
    #[test]
    fn more_data_is_a_page_carrying_a_resume_handle() {
        let page = response(&build(
            &[("alpha", 0, "first")],
            9,
            0x0000_002A,
            ERROR_MORE_DATA,
        ))
        .unwrap();
        assert!(page.more);
        assert_eq!(page.resume, 0x2A);
        assert_eq!(page.total, 9);
        assert_eq!(page.shares.len(), 1);
    }

    #[test]
    fn any_other_return_code_fails_the_call() {
        assert_eq!(response(&build(&[], 0, 0, 5)), Err(SrvsvcError::Failed(5)));
    }

    #[test]
    fn a_reply_at_another_information_level_is_refused() {
        let mut stub = build(&[("alpha", 0, "")], 1, 0, WERR_OK);
        stub[..4].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(response(&stub), Err(SrvsvcError::Level(2)));
    }

    #[test]
    fn a_reply_whose_two_levels_disagree_is_refused() {
        let mut stub = build(&[("alpha", 0, "")], 1, 0, WERR_OK);
        stub[4..8].copy_from_slice(&2u32.to_le_bytes());
        assert_eq!(
            response(&stub),
            Err(SrvsvcError::LevelMismatch { outer: 1, inner: 2 })
        );
    }

    /// A reply that says it holds fewer shares in total than it just returned
    /// is a reply disagreeing with itself, and it is refused rather than
    /// decoded to whichever half is believed.
    #[test]
    fn a_total_below_the_entries_returned_is_refused() {
        assert_eq!(
            response(&build(&[("alpha", 0, ""), ("beta", 0, "")], 1, 0, WERR_OK)),
            Err(SrvsvcError::TotalBelowEntries {
                entries: 2,
                total: 1
            })
        );
    }

    /// An entry count above the array's own conformance count is the same class
    /// of self-contradiction, one layer in.
    #[test]
    fn an_entry_count_above_the_arrays_conformance_is_refused() {
        let mut stub = build(&[("alpha", 0, "")], 1, 0, WERR_OK);
        // EntriesRead sits at 12 and the array's maximum count at 20.
        stub[12..16].copy_from_slice(&1u32.to_le_bytes());
        stub[20..24].copy_from_slice(&0u32.to_le_bytes());
        assert_eq!(
            response(&stub),
            Err(SrvsvcError::ArrayTooSmall {
                entries: 1,
                maximum: 0
            })
        );
    }

    /// A stub cut short mid-walk fails rather than returning the entries that
    /// happened to fit — which is what a decoder handed one PDU of a
    /// multi-fragment reply is holding.
    #[test]
    fn a_stub_cut_short_fails_rather_than_returning_what_fitted() {
        let whole = build(&[("alpha", 0, "one"), ("beta", 0, "two")], 2, 0, WERR_OK);
        for cut in [24, 40, 60, whole.len() - 4] {
            assert!(
                matches!(response(&whole[..cut]), Err(SrvsvcError::Ndr(_))),
                "a stub cut at {cut} decoded"
            );
        }
    }

    /// Builds a reply stub the way a server does, independently of this
    /// module's own reader.
    pub(crate) fn build(
        shares: &[(&str, u32, &str)],
        total: u32,
        resume: u32,
        code: u32,
    ) -> Vec<u8> {
        fn string(out: &mut Vec<u8>, text: &str) {
            let units: Vec<u16> = text.encode_utf16().chain([0]).collect();
            out.extend_from_slice(&(units.len() as u32).to_le_bytes());
            out.extend_from_slice(&0u32.to_le_bytes());
            out.extend_from_slice(&(units.len() as u32).to_le_bytes());
            for unit in units {
                out.extend_from_slice(&unit.to_le_bytes());
            }
            out.resize(out.len().next_multiple_of(4), 0);
        }

        let mut out = Vec::new();
        let mut referent = 0x0002_0014u32;
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&1u32.to_le_bytes());
        out.extend_from_slice(&0x0002_000Cu32.to_le_bytes());
        out.extend_from_slice(&(shares.len() as u32).to_le_bytes());
        out.extend_from_slice(&0x0002_0010u32.to_le_bytes());
        out.extend_from_slice(&(shares.len() as u32).to_le_bytes());
        for (_, kind, _) in shares {
            out.extend_from_slice(&referent.to_le_bytes());
            out.extend_from_slice(&kind.to_le_bytes());
            out.extend_from_slice(&(referent + 4).to_le_bytes());
            referent += 8;
        }
        for (name, _, comment) in shares {
            string(&mut out, name);
            string(&mut out, comment);
        }
        out.extend_from_slice(&total.to_le_bytes());
        out.extend_from_slice(&referent.to_le_bytes());
        out.extend_from_slice(&resume.to_le_bytes());
        out.extend_from_slice(&code.to_le_bytes());
        out
    }
}
