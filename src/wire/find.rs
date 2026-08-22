//! `TRANS2_FIND_FIRST2`, `TRANS2_FIND_NEXT2`, and the directory entry chain.
//!
//! Both requests ask for information level `SMB_FIND_FILE_BOTH_DIRECTORY_INFO`,
//! which is the level every rule about entries here is written against.
//!
//! The chain walk is bounded by two terminators and needs both. Windows
//! zero-terminates its chain and leaves trailing padding; Samba's last entry
//! instead points just past itself, so the chain lands exactly on the
//! `DataCount` boundary. Each convention defeats a walker honouring only the
//! other — a `DataCount` bound alone does not recognise Windows's zero as a
//! terminator, and the zero alone never meets one on Samba, being sent past the
//! end of the data.

use binrw::binrw;

use super::header::command;
use super::{Message, WireError, body, from_utf16, read_words, write_words};

/// TRANS2 subcommand `TRANS2_FIND_FIRST2`.
pub const SUBCOMMAND_FIND_FIRST2: u16 = 0x0001;

/// TRANS2 subcommand `TRANS2_FIND_NEXT2`.
pub const SUBCOMMAND_FIND_NEXT2: u16 = 0x0002;

/// `SMB_FIND_FILE_BOTH_DIRECTORY_INFO`.
pub const INFO_LEVEL_BOTH_DIRECTORY_INFO: u16 = 0x0104;

/// Directory, hidden and system. It decides whether hidden and system entries
/// appear in a listing at all, and with that whether a recursive delete can
/// empty a directory that holds them.
pub const SEARCH_ATTRIBUTES: u16 = 0x0016;

/// Close the search after this request.
pub const FLAG_CLOSE_AFTER_REQUEST: u16 = 0x0001;
/// Close the search when it reaches end of stream.
pub const FLAG_CLOSE_AT_EOS: u16 = 0x0002;
/// Return resume keys, which this crate does not ask for.
pub const FLAG_RETURN_RESUME_KEYS: u16 = 0x0004;
/// Continue from where the server left off, rather than from a resume key.
pub const FLAG_CONTINUE_FROM_LAST: u16 = 0x0008;

/// The smallest a `SMB_FIND_FILE_BOTH_DIRECTORY_INFO` entry can be: the fixed
/// fields, with an empty name.
pub const MIN_ENTRY_LEN: usize = 94;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FindFirst2Words {
    search_attributes: u16,
    search_count: u16,
    flags: u16,
    information_level: u16,
    search_storage_type: u32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FindNext2Words {
    sid: u16,
    search_count: u16,
    information_level: u16,
    resume_key: u32,
    flags: u16,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FindFirst2ReplyWords {
    sid: u16,
    search_count: u16,
    end_of_search: u16,
    ea_error_offset: u16,
    last_name_offset: u16,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FindNext2ReplyWords {
    search_count: u16,
    end_of_search: u16,
    ea_error_offset: u16,
    last_name_offset: u16,
}

/// The parameter block of a `TRANS2_FIND_FIRST2` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindFirst2Params {
    /// Which attributes a matching entry may carry. See [`SEARCH_ATTRIBUTES`].
    pub search_attributes: u16,
    /// How many entries to ask for. It is advisory: a server returns whatever
    /// fits, and what bounds a page is `MaxDataCount`.
    pub search_count: u16,
    /// The `SMB_FIND_*` flags.
    pub flags: u16,
    /// The information level. See [`INFO_LEVEL_BOTH_DIRECTORY_INFO`].
    pub information_level: u16,
    /// The pattern to search on.
    pub pattern: String,
}

impl FindFirst2Params {
    /// Encodes the parameter block.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let words = FindFirst2Words {
            search_attributes: self.search_attributes,
            search_count: self.search_count,
            flags: self.flags,
            information_level: self.information_level,
            search_storage_type: 0,
        };
        let mut out = write_words(&words)?;
        out.extend_from_slice(&super::utf16z(&self.pattern));
        Ok(out)
    }

    /// Decodes a parameter block.
    pub fn decode(parameters: &[u8]) -> Result<Self, WireError> {
        let (fixed, name) = parameters
            .split_at_checked(12)
            .ok_or(WireError::Truncated {
                part: "FIND_FIRST2 parameters",
                declared: 12,
                length: parameters.len(),
            })?;
        let words: FindFirst2Words = read_words(fixed)?;
        Ok(Self {
            search_attributes: words.search_attributes,
            search_count: words.search_count,
            flags: words.flags,
            information_level: words.information_level,
            pattern: from_utf16("FileName", 0, trim_terminator(name))?,
        })
    }
}

/// The parameter block of a `TRANS2_FIND_NEXT2` request.
///
/// It is not self-contained: it repeats the search id the `FIND_FIRST2` reply
/// returned, re-sends the pattern, and asks the server to continue from its own
/// position. Continuation is server-side and the client keeps no resume point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FindNext2Params {
    /// The search id.
    pub sid: u16,
    /// How many entries to ask for.
    pub search_count: u16,
    /// The information level.
    pub information_level: u16,
    /// Zero, since continuation is by [`FLAG_CONTINUE_FROM_LAST`].
    pub resume_key: u32,
    /// The `SMB_FIND_*` flags.
    pub flags: u16,
    /// The pattern the search was opened on.
    pub pattern: String,
}

impl FindNext2Params {
    /// Encodes the parameter block.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        let words = FindNext2Words {
            sid: self.sid,
            search_count: self.search_count,
            information_level: self.information_level,
            resume_key: self.resume_key,
            flags: self.flags,
        };
        let mut out = write_words(&words)?;
        out.extend_from_slice(&super::utf16z(&self.pattern));
        Ok(out)
    }

    /// Decodes a parameter block.
    pub fn decode(parameters: &[u8]) -> Result<Self, WireError> {
        let (fixed, name) = parameters
            .split_at_checked(12)
            .ok_or(WireError::Truncated {
                part: "FIND_NEXT2 parameters",
                declared: 12,
                length: parameters.len(),
            })?;
        let words: FindNext2Words = read_words(fixed)?;
        Ok(Self {
            sid: words.sid,
            search_count: words.search_count,
            information_level: words.information_level,
            resume_key: words.resume_key,
            flags: words.flags,
            pattern: from_utf16("FileName", 0, trim_terminator(name))?,
        })
    }
}

/// What a FIND reply's parameter block says about the page it carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindReply {
    /// The search id, which only a `FIND_FIRST2` reply carries.
    pub sid: Option<u16>,
    /// How many entries the server says it returned.
    pub search_count: u16,
    /// Non-zero when the server has no more entries after this page.
    pub end_of_search: u16,
    /// Where an extended-attribute error occurred, if one did.
    pub ea_error_offset: u16,
    /// Where the last entry's name begins. Read because the reply carries it,
    /// not because anything is read back into a request.
    pub last_name_offset: u16,
}

impl FindReply {
    /// Decodes a `FIND_FIRST2` reply's parameter block.
    pub fn decode_first(parameters: &[u8]) -> Result<Self, WireError> {
        let words: FindFirst2ReplyWords = read_words(parameters)?;
        Ok(Self {
            sid: Some(words.sid),
            search_count: words.search_count,
            end_of_search: words.end_of_search,
            ea_error_offset: words.ea_error_offset,
            last_name_offset: words.last_name_offset,
        })
    }

    /// Decodes a `FIND_NEXT2` reply's parameter block, which carries no search
    /// id.
    pub fn decode_next(parameters: &[u8]) -> Result<Self, WireError> {
        let words: FindNext2ReplyWords = read_words(parameters)?;
        Ok(Self {
            sid: None,
            search_count: words.search_count,
            end_of_search: words.end_of_search,
            ea_error_offset: words.ea_error_offset,
            last_name_offset: words.last_name_offset,
        })
    }
}

/// One `SMB_FIND_FILE_BOTH_DIRECTORY_INFO` entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectoryEntry {
    /// The server's index for the entry.
    pub file_index: u32,
    /// Creation time, in Windows FILETIME units.
    pub creation_time: i64,
    /// Last access time.
    pub last_access_time: i64,
    /// Last write time.
    pub last_write_time: i64,
    /// Last metadata change time.
    pub change_time: i64,
    /// The file's length.
    pub end_of_file: u64,
    /// Space allocated to the file.
    pub allocation_size: u64,
    /// The file's attributes.
    pub ext_file_attributes: u32,
    /// The size of the entry's extended attributes.
    pub ea_size: u32,
    /// The 8.3 name, where the server keeps one.
    pub short_name: String,
    /// The name.
    pub file_name: String,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EntryWords {
    next_entry_offset: u32,
    file_index: u32,
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    end_of_file: u64,
    allocation_size: u64,
    ext_file_attributes: u32,
    file_name_length: u32,
    ea_size: u32,
    short_name_length: u8,
    reserved: u8,
    short_name: [u8; 24],
}

/// Walks the entry chain of a reassembled FIND reply, cross-checking the count
/// against what the reply says it returned.
///
/// `data` is the reply's whole data block. It is never one message's worth: an
/// entry straddles the fragment boundary in the committed corpus, so a walk
/// over a single message parses a truncated entry.
///
/// An entry's size is never computed from an assumed stride. Samba pads to 4
/// bytes and Windows mostly to 8, and one server is not even internally
/// consistent with itself — the `.` entry has a 96-byte body under a
/// `NextEntryOffset` of 100 in one capture and 96 in another, from the same
/// server for identical content. The walk follows `NextEntryOffset`, which
/// carries whatever padding there is.
///
/// A mismatch against `search_count` is an error rather than a logged oddity:
/// the chain and the count are two statements about the same reply.
pub fn walk_entries(data: &[u8], search_count: u16) -> Result<Vec<DirectoryEntry>, WireError> {
    let mut entries = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        let entry = data.get(offset..).ok_or(WireError::Truncated {
            part: "directory entry",
            declared: offset,
            length: data.len(),
        })?;
        let fixed = entry.get(..MIN_ENTRY_LEN).ok_or(WireError::Truncated {
            part: "directory entry",
            declared: MIN_ENTRY_LEN,
            length: entry.len(),
        })?;
        let words: EntryWords = read_words(fixed)?;

        let position = entries.len();
        // Saturating rather than checked: these are server-supplied counts, and
        // an arithmetic overflow on a 32-bit target would be a panic in a
        // parser an unauthenticated peer reaches.
        let name_length = words.file_name_length as usize;
        let name_end = MIN_ENTRY_LEN.saturating_add(name_length);
        let raw_name = entry
            .get(MIN_ENTRY_LEN..name_end)
            .ok_or(WireError::Truncated {
                part: "directory entry FileName",
                declared: name_end,
                length: entry.len(),
            })?;
        let short_length = usize::from(words.short_name_length).min(words.short_name.len());

        entries.push(DirectoryEntry {
            file_index: words.file_index,
            creation_time: words.creation_time,
            last_access_time: words.last_access_time,
            last_write_time: words.last_write_time,
            change_time: words.change_time,
            end_of_file: words.end_of_file,
            allocation_size: words.allocation_size,
            ext_file_attributes: words.ext_file_attributes,
            ea_size: words.ea_size,
            short_name: from_utf16("ShortName", position, &words.short_name[..short_length])?,
            file_name: from_utf16("FileName", position, raw_name)?,
        });

        let next = words.next_entry_offset as usize;
        // The zero terminator is tested first, and the order is the rule. Test
        // the minimum first and `0 < 94` rejects every Windows listing as
        // malformed; skip the minimum entirely and a walker advancing by a zero
        // offset sits on one entry forever.
        if next == 0 {
            break;
        }
        if next < MIN_ENTRY_LEN {
            return Err(WireError::EntryOffsetTooSmall {
                offset,
                next,
                minimum: MIN_ENTRY_LEN,
            });
        }
        offset = offset.saturating_add(next);
    }

    if entries.len() != usize::from(search_count) {
        return Err(WireError::EntryCountMismatch {
            walked: entries.len(),
            search_count,
        });
    }
    Ok(entries)
}

/// An `SMB_COM_FIND_CLOSE2` request, which releases a search the server still
/// holds.
///
/// It is a standalone SMB command and not a TRANS2 subcommand, and it has no
/// offline oracle of any kind: the reference library's `EncodeFindClose2` is
/// shaped as a TRANS2 parameter block, has no production caller anywhere, and
/// its own source records that sending the real thing would need a new command
/// type. So that encoder is evidence the command was never sent rather than a
/// reference for sending it, and this is written from \[MS-CIFS\] 2.2.4.55.
///
/// It is the other half of closing a search. The half that covers a listing
/// drained to its end is `SMB_FIND_CLOSE_AT_EOS` on the FIND_FIRST2 and on
/// every FIND_NEXT2; this covers the listing dropped before then, which lazy
/// listing makes ordinary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindClose2Request {
    /// The search to release, as the FIND_FIRST2 reply named it.
    pub sid: u16,
}

impl FindClose2Request {
    /// Encodes the command body. One word, and an empty byte area.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        Ok(body(&self.sid.to_le_bytes(), &[]))
    }

    /// Decodes a find-close request.
    pub fn decode(message: &Message) -> Result<Self, WireError> {
        message.expect_words(command::FIND_CLOSE2, &[1], "1")?;
        Ok(Self {
            sid: u16::from_le_bytes([message.words()[0], message.words()[1]]),
        })
    }
}

/// A find-close response, which carries nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FindClose2Response;

impl FindClose2Response {
    /// Decodes a find-close response.
    ///
    /// Zero words is this command's successful shape, not the error shape.
    pub fn decode(message: &Message) -> Result<Self, WireError> {
        message.expect_words(command::FIND_CLOSE2, &[0], "0")?;
        Ok(Self)
    }

    /// Encodes the command body.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        Ok(body(&[], &[]))
    }
}

/// Drops the trailing null unit of a UTF-16LE string, if there is one.
fn trim_terminator(bytes: &[u8]) -> &[u8] {
    match bytes.len().checked_sub(2) {
        Some(end) if bytes[end..] == [0, 0] => &bytes[..end],
        _ => bytes,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal entry with a name, laid out the way a server lays one out.
    fn entry(next: u32, name: &str) -> Vec<u8> {
        let name: Vec<u8> = name.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut out = vec![0u8; MIN_ENTRY_LEN];
        out[0..4].copy_from_slice(&next.to_le_bytes());
        out[60..64].copy_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(&name);
        out
    }

    /// Windows's convention: a zero `NextEntryOffset`, and six bytes of
    /// trailing padding the walk never reaches.
    #[test]
    fn a_zero_next_entry_offset_ends_the_chain() {
        let mut data = entry(100, ".");
        data.resize(100, 0);
        data.extend_from_slice(&entry(0, "subdir"));
        data.resize(data.len() + 6, 0);

        let walked = walk_entries(&data, 2).unwrap();
        assert_eq!(walked.len(), 2);
        assert_eq!(walked[1].file_name, "subdir");
    }

    /// Samba's convention: the last entry points just past itself, landing
    /// exactly on the end of the data.
    #[test]
    fn the_data_bound_ends_a_chain_that_never_zero_terminates() {
        let mut data = entry(112, "alpha.txt");
        data.resize(112, 0);
        data.extend_from_slice(&entry(112, "beta.bin"));
        data.resize(224, 0);

        let walked = walk_entries(&data, 2).unwrap();
        assert_eq!(walked.len(), 2);
        assert_eq!(walked[1].file_name, "beta.bin");
    }

    /// Testing the minimum before the zero would reject every Windows listing,
    /// because `0 < 94`.
    #[test]
    fn the_zero_terminator_is_tested_before_the_minimum() {
        let data = entry(0, ".");
        assert_eq!(walk_entries(&data, 1).unwrap().len(), 1);
    }

    /// A `NextEntryOffset` below the minimum would re-parse overlapping bytes
    /// into fabricated entries.
    #[test]
    fn an_offset_below_the_minimum_entry_size_is_refused() {
        let mut data = entry(8, ".");
        data.resize(200, 0);
        assert!(matches!(
            walk_entries(&data, 2),
            Err(WireError::EntryOffsetTooSmall {
                offset: 0,
                next: 8,
                minimum: 94
            })
        ));
    }

    /// The chain and the count are two statements about the same reply.
    #[test]
    fn the_walked_count_is_cross_checked_against_search_count() {
        let data = entry(0, "alpha.txt");
        assert!(matches!(
            walk_entries(&data, 2),
            Err(WireError::EntryCountMismatch {
                walked: 1,
                search_count: 2
            })
        ));
    }

    /// A name that is not valid UTF-16 fails the listing rather than arriving
    /// lossily decoded.
    #[test]
    fn an_invalid_name_fails_the_listing() {
        let mut data = entry(0, "ab");
        // An unpaired high surrogate.
        data[MIN_ENTRY_LEN] = 0x00;
        data[MIN_ENTRY_LEN + 1] = 0xD8;
        assert!(matches!(
            walk_entries(&data, 1),
            Err(WireError::InvalidUtf16 {
                field: "FileName",
                position: 0,
                ..
            })
        ));
    }
}
