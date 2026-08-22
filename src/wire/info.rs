//! The TRANS2 information subcommands: query and set, by path, by handle and
//! by volume.
//!
//! **Information-level numbers repeat across subcommands and mean nothing
//! apart from the one that carries them.** `0x0104` is a set-file level here
//! and a find level in [`super::find`]; `0x0101` is a query-file level, a
//! set-file level, a find level and a query-fs level at once. So the constants
//! are grouped by subcommand rather than pooled into one table, which is what
//! the reference does too and for the same reason.
//!
//! **A zero field in `SMB_SET_FILE_BASIC_INFO` means "do not change".** The
//! level carries four FILETIMEs and an attribute word, and a zero in any of
//! them tells the server to leave that field alone. Two verbs share this one
//! wire level, each sending zeros for the other's fields, which is why
//! [`BasicInfo`] carries `Option`s rather than values.

use binrw::binrw;

use super::{WireError, read_words, utf16z, write_words};

/// `TRANS2_QUERY_FS_INFORMATION`.
pub const SUBCOMMAND_QUERY_FS_INFORMATION: u16 = 0x0003;

/// `TRANS2_QUERY_PATH_INFORMATION`.
pub const SUBCOMMAND_QUERY_PATH_INFORMATION: u16 = 0x0005;

/// `TRANS2_SET_PATH_INFORMATION`.
pub const SUBCOMMAND_SET_PATH_INFORMATION: u16 = 0x0006;

/// `TRANS2_SET_FILE_INFORMATION`.
pub const SUBCOMMAND_SET_FILE_INFORMATION: u16 = 0x0008;

/// Query-path and query-file levels.
pub mod query_level {
    /// `SMB_QUERY_FILE_BASIC_INFO`: the four timestamps and the attributes.
    pub const BASIC_INFO: u16 = 0x0101;
    /// `SMB_QUERY_FILE_STANDARD_INFO`: the size and the allocation size.
    ///
    /// Neither level carries both halves, which is why a stat is two queries.
    pub const STANDARD_INFO: u16 = 0x0102;
}

/// Set-path and set-file levels.
pub mod set_level {
    /// `SMB_SET_FILE_BASIC_INFO`: times and attributes together, needing no
    /// open handle when it is sent as a set-path.
    pub const BASIC_INFO: u16 = 0x0101;
    /// `FILE_END_OF_FILE_INFORMATION`: the new length as eight little-endian
    /// bytes and nothing else. A set-file level, on a handle opened for
    /// writing.
    pub const END_OF_FILE_INFORMATION: u16 = 0x0104;
}

/// Query-fs levels.
pub mod fs_level {
    /// `SMB_QUERY_FS_SIZE_INFO`, whose unit counts are 64-bit.
    pub const SIZE_INFO: u16 = 0x0103;
    /// `SMB_INFO_ALLOCATION`, the legacy level, whose counts are 32-bit and so
    /// wrap on a large volume. It is the fallback and the reason
    /// `FsStatistics` says which level answered.
    pub const ALLOCATION: u16 = 0x0001;
}

/// `FILE_ATTRIBUTE_DIRECTORY`.
pub const ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;

/// `FILE_ATTRIBUTE_NORMAL`, which is what actually clears every other
/// attribute: a zero attribute word means "do not change" and would return
/// success having changed nothing.
pub const ATTRIBUTE_NORMAL: u32 = 0x0000_0080;

/// The parameter block of a `TRANS2_QUERY_PATH_INFORMATION`.
///
/// `capture/0011-c2s-cmd32.bin` pins it: level `0x0101`, four reserved bytes,
/// then the path as null-terminated UTF-16LE.
pub fn query_path_parameters(level: u16, path: &str) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&level.to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&utf16z(path));
    out
}

/// The parameter block of a `TRANS2_SET_PATH_INFORMATION`, which is the query
/// form exactly — the data block is what differs.
pub fn set_path_parameters(level: u16, path: &str) -> Vec<u8> {
    query_path_parameters(level, path)
}

/// The parameter block of a `TRANS2_SET_FILE_INFORMATION`: the handle, the
/// level, and a reserved word the query-by-handle form does not carry.
pub fn set_file_parameters(fid: u16, level: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(6);
    out.extend_from_slice(&fid.to_le_bytes());
    out.extend_from_slice(&level.to_le_bytes());
    out.extend_from_slice(&0u16.to_le_bytes());
    out
}

/// The parameter block of a `TRANS2_QUERY_FS_INFORMATION`, which is the level
/// alone: the query is scoped to the tree it is sent on and takes neither a
/// path nor a handle.
pub fn query_fs_parameters(level: u16) -> Vec<u8> {
    level.to_le_bytes().to_vec()
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct BasicInfoWords {
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    attributes: u32,
    reserved: u32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct StandardInfoWords {
    allocation_size: u64,
    end_of_file: u64,
    number_of_links: u32,
    delete_pending: u8,
    directory: u8,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SizeInfoWords {
    total_allocation_units: u64,
    total_free_allocation_units: u64,
    sectors_per_allocation_unit: u32,
    bytes_per_sector: u32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct AllocationWords {
    file_system_id: u32,
    sectors_per_allocation_unit: u32,
    total_allocation_units: u32,
    free_allocation_units: u32,
    bytes_per_sector: u16,
}

/// `SMB_QUERY_FILE_BASIC_INFO` as it comes back, and
/// `SMB_SET_FILE_BASIC_INFO` as it goes out.
///
/// The fields are `Option` on the way out and values on the way in: a zero on
/// the wire means "do not change", so a caller setting a modification time must
/// have some way of not also asserting a creation time it does not know.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct BasicInfo {
    /// When the file was created, in FILETIME units.
    pub creation_time: Option<i64>,
    /// When it was last read.
    pub last_access_time: Option<i64>,
    /// When it was last written.
    pub last_write_time: Option<i64>,
    /// When its metadata last changed.
    pub change_time: Option<i64>,
    /// The attribute word.
    pub attributes: Option<u32>,
}

impl BasicInfo {
    /// The data block of an `SMB_SET_FILE_BASIC_INFO`, `None` encoded as the
    /// zero that leaves a field as it was.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        write_words(&BasicInfoWords {
            creation_time: self.creation_time.unwrap_or(0),
            last_access_time: self.last_access_time.unwrap_or(0),
            last_write_time: self.last_write_time.unwrap_or(0),
            change_time: self.change_time.unwrap_or(0),
            attributes: self.attributes.unwrap_or(0),
            reserved: 0,
        })
    }

    /// Decodes a `SMB_QUERY_FILE_BASIC_INFO` reply.
    ///
    /// The reserved word the set form carries is not required back: the
    /// container answers this level with 36 bytes and not 40
    /// (`capture/0012-s2c-cmd32.bin`), so requiring the fifth word would refuse
    /// a conforming reply.
    pub fn decode(data: &[u8]) -> Result<Self, WireError> {
        const WITHOUT_RESERVED: usize = 36;
        let block = data.get(..WITHOUT_RESERVED).ok_or(WireError::Truncated {
            part: "SMB_QUERY_FILE_BASIC_INFO",
            declared: WITHOUT_RESERVED,
            length: data.len(),
        })?;
        let mut padded = block.to_vec();
        padded.extend_from_slice(&[0; 4]);
        let words: BasicInfoWords = read_words(&padded)?;
        Ok(Self {
            creation_time: Some(words.creation_time),
            last_access_time: Some(words.last_access_time),
            last_write_time: Some(words.last_write_time),
            change_time: Some(words.change_time),
            attributes: Some(words.attributes),
        })
    }
}

/// `SMB_QUERY_FILE_STANDARD_INFO`: the half of a stat the basic level does not
/// carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandardInfo {
    /// Space allocated to the file.
    pub allocation_size: u64,
    /// The file's length.
    pub end_of_file: u64,
    /// Hard links to it.
    pub number_of_links: u32,
    /// Whether a delete is pending on it.
    pub delete_pending: bool,
    /// Whether it is a directory.
    pub directory: bool,
}

impl StandardInfo {
    /// Decodes a `SMB_QUERY_FILE_STANDARD_INFO` reply.
    pub fn decode(data: &[u8]) -> Result<Self, WireError> {
        const LEN: usize = 22;
        let block = data.get(..LEN).ok_or(WireError::Truncated {
            part: "SMB_QUERY_FILE_STANDARD_INFO",
            declared: LEN,
            length: data.len(),
        })?;
        let words: StandardInfoWords = read_words(block)?;
        Ok(Self {
            allocation_size: words.allocation_size,
            end_of_file: words.end_of_file,
            number_of_links: words.number_of_links,
            delete_pending: words.delete_pending != 0,
            directory: words.directory != 0,
        })
    }
}

/// A volume's size, from whichever of the two levels answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FsSize {
    /// Allocation units on the volume.
    pub total_units: u64,
    /// Allocation units still free.
    pub free_units: u64,
    /// Sectors making up one allocation unit.
    pub sectors_per_unit: u32,
    /// Bytes per sector.
    pub bytes_per_sector: u32,
}

impl FsSize {
    /// Decodes `SMB_QUERY_FS_SIZE_INFO`.
    pub fn decode_size_info(data: &[u8]) -> Result<Self, WireError> {
        const LEN: usize = 24;
        let block = data.get(..LEN).ok_or(WireError::Truncated {
            part: "SMB_QUERY_FS_SIZE_INFO",
            declared: LEN,
            length: data.len(),
        })?;
        let words: SizeInfoWords = read_words(block)?;
        Ok(Self {
            total_units: words.total_allocation_units,
            free_units: words.total_free_allocation_units,
            sectors_per_unit: words.sectors_per_allocation_unit,
            bytes_per_sector: words.bytes_per_sector,
        })
    }

    /// Decodes `SMB_INFO_ALLOCATION`, whose counts are 32-bit.
    pub fn decode_allocation(data: &[u8]) -> Result<Self, WireError> {
        const LEN: usize = 18;
        let block = data.get(..LEN).ok_or(WireError::Truncated {
            part: "SMB_INFO_ALLOCATION",
            declared: LEN,
            length: data.len(),
        })?;
        let words: AllocationWords = read_words(block)?;
        Ok(Self {
            total_units: u64::from(words.total_allocation_units),
            free_units: u64::from(words.free_allocation_units),
            sectors_per_unit: words.sectors_per_allocation_unit,
            bytes_per_sector: u32::from(words.bytes_per_sector),
        })
    }

    /// The unit counts multiplied out, so that every caller does not.
    ///
    /// Saturating, because the three factors are server-supplied and their
    /// product need not fit: a wrapped number would be worse than a clamped
    /// one, and this is the field a caller compares against a file size.
    pub fn bytes(&self, units: u64) -> u64 {
        units
            .saturating_mul(u64::from(self.sectors_per_unit))
            .saturating_mul(u64::from(self.bytes_per_sector))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Message;
    use crate::wire::transaction::TransactionRequest;
    use std::fs;
    use std::path::Path;

    fn fixture(relative: &str) -> Message {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join(relative);
        let bytes = fs::read(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        Message::parse(bytes[4..].to_vec()).unwrap_or_else(|error| panic!("{relative}: {error}"))
    }

    /// The parameter block this crate builds is the one the reference sent,
    /// byte for byte, on both levels a stat uses.
    #[test]
    fn the_query_path_parameters_are_the_captured_ones() {
        for (name, level) in [
            ("capture/0011-c2s-cmd32.bin", query_level::BASIC_INFO),
            ("capture/0013-c2s-cmd32.bin", query_level::STANDARD_INFO),
        ] {
            let captured = TransactionRequest::decode(&fixture(name)).unwrap();
            assert_eq!(captured.setup, vec![SUBCOMMAND_QUERY_PATH_INFORMATION]);
            assert_eq!(
                captured.parameters,
                query_path_parameters(level, "alpha.txt"),
                "{name}"
            );
        }
    }

    /// The two halves of a stat, decoded off the replies the container sent.
    #[test]
    fn a_stat_reads_its_two_halves_off_the_two_captured_replies() {
        let basic = TransactionRequest::decode(&fixture("capture/0011-c2s-cmd32.bin")).unwrap();
        assert_eq!(basic.parameters[..2], query_level::BASIC_INFO.to_le_bytes());

        let reply = crate::wire::transaction::TransactionResponse::decode(&fixture(
            "capture/0012-s2c-cmd32.bin",
        ))
        .unwrap();
        // The reply carries 36 bytes and not the 40 the set form sends.
        assert_eq!(reply.data.len(), 36);
        let info = BasicInfo::decode(&reply.data).unwrap();
        assert_eq!(info.attributes, Some(ATTRIBUTE_NORMAL));
        assert!(info.last_write_time.unwrap() > 0);

        let reply = crate::wire::transaction::TransactionResponse::decode(&fixture(
            "capture/0014-s2c-cmd32.bin",
        ))
        .unwrap();
        let info = StandardInfo::decode(&reply.data).unwrap();
        assert_eq!(info.end_of_file, 11);
        assert_eq!(info.allocation_size, 4096);
        assert!(!info.directory);
    }

    /// A `None` is the zero that leaves a field alone, and the block is the 40
    /// bytes the level defines rather than the 36 a reply may carry.
    #[test]
    fn an_unset_field_encodes_as_the_zero_that_changes_nothing() {
        let block = BasicInfo {
            last_write_time: Some(0x0123_4567_89AB_CDEF),
            ..BasicInfo::default()
        }
        .encode()
        .unwrap();
        assert_eq!(block.len(), 40);
        assert_eq!(block[..8], [0; 8]);
        assert_eq!(block[16..24], 0x0123_4567_89AB_CDEFi64.to_le_bytes());
        assert_eq!(block[32..40], [0; 8]);
    }

    /// The legacy level's 32-bit counts widen without wrapping, and the
    /// multiplication saturates rather than overflowing on a server's numbers.
    #[test]
    fn the_legacy_level_widens_and_the_arithmetic_saturates() {
        let mut data = Vec::new();
        data.extend_from_slice(&0u32.to_le_bytes());
        data.extend_from_slice(&8u32.to_le_bytes());
        data.extend_from_slice(&u32::MAX.to_le_bytes());
        data.extend_from_slice(&1_000u32.to_le_bytes());
        data.extend_from_slice(&512u16.to_le_bytes());

        let size = FsSize::decode_allocation(&data).unwrap();
        assert_eq!(size.total_units, u64::from(u32::MAX));
        assert_eq!(size.bytes(size.free_units), 1_000 * 8 * 512);

        let huge = FsSize {
            total_units: u64::MAX,
            free_units: 0,
            sectors_per_unit: 8,
            bytes_per_sector: 512,
        };
        assert_eq!(huge.bytes(huge.total_units), u64::MAX);
    }
}
