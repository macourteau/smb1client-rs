//! `SMB_COM_NT_CREATE_ANDX`, `SMB_COM_CLOSE` and `SMB_COM_RENAME`.
//!
//! Two of the three name-alignment sites are here, and they do not solve the
//! problem the same way. `NT_CREATE_ANDX` writes a pad byte; `SMB_COM_RENAME`
//! writes one before its *second* name and none before its first. The third
//! site is `TREE_CONNECT_ANDX`, which declares a password byte instead.

use binrw::binrw;

use super::andx::AndX;
use super::header::command;
use super::offsets::{ByteArea, require_word_aligned};
use super::{Message, WireError, body, from_utf16, read_words, utf16z, write_words};

/// The `WordCount` of an `NT_CREATE_ANDX` request.
const CREATE_REQUEST_WORDS: u8 = 24;

/// The `WordCount` of an `NT_CREATE_ANDX` response.
const CREATE_RESPONSE_WORDS: u8 = 34;

/// The `WordCount` of a close request.
const CLOSE_REQUEST_WORDS: u8 = 3;

/// The `WordCount` of a rename request.
const RENAME_REQUEST_WORDS: u8 = 1;

/// The byte that introduces each name in a rename's byte area.
const BUFFER_FORMAT_ASCII: u8 = 0x04;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CreateRequestWords {
    andx: AndX,
    reserved: u8,
    name_length: u16,
    flags: u32,
    root_directory_fid: u32,
    desired_access: u32,
    allocation_size: u64,
    ext_file_attributes: u32,
    share_access: u32,
    create_disposition: u32,
    create_options: u32,
    impersonation_level: u32,
    security_flags: u8,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CreateResponseWords {
    andx: AndX,
    oplock_level: u8,
    fid: u16,
    create_action: u32,
    creation_time: i64,
    last_access_time: i64,
    last_write_time: i64,
    change_time: i64,
    ext_file_attributes: u32,
    allocation_size: u64,
    end_of_file: u64,
    resource_type: u16,
    nm_pipe_status: u16,
    directory: u8,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CloseRequestWords {
    fid: u16,
    last_time_modified: u32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RenameRequestWords {
    search_attributes: u16,
}

/// An `NT_CREATE_ANDX` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NtCreateAndxRequest {
    /// Oplock and extended-response request bits.
    pub flags: u32,
    /// The directory a relative name is resolved against, or zero.
    pub root_directory_fid: u32,
    /// The access rights asked for.
    pub desired_access: u32,
    /// The size to allocate on creation.
    pub allocation_size: u64,
    /// The attributes to give a file being created.
    pub ext_file_attributes: u32,
    /// What other openers may do while this handle is open.
    pub share_access: u32,
    /// Open, create, overwrite, or one of the conditional forms.
    pub create_disposition: u32,
    /// Directory-or-not and the write-through and delete-on-close bits.
    pub create_options: u32,
    /// The impersonation level offered to the server.
    pub impersonation_level: u32,
    /// Context-tracking bits.
    pub security_flags: u8,
    /// The path, relative to the tree.
    pub name: String,
}

impl NtCreateAndxRequest {
    /// Encodes the command body.
    ///
    /// The byte area begins at 83 — header 32, `WordCount` 1, parameters 48,
    /// `ByteCount` 2 — which is odd, so a single pad byte precedes the name.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        let name = utf16z(&self.name);
        let mut area = ByteArea::for_word_count(usize::from(CREATE_REQUEST_WORDS));
        area.align_to(2);
        require_word_aligned("Name", area.offset())?;
        area.put(&name);

        let words = CreateRequestWords {
            andx: AndX::NONE,
            reserved: 0,
            // The terminator is not counted.
            name_length: (name.len() - 2) as u16,
            flags: self.flags,
            root_directory_fid: self.root_directory_fid,
            desired_access: self.desired_access,
            allocation_size: self.allocation_size,
            ext_file_attributes: self.ext_file_attributes,
            share_access: self.share_access,
            create_disposition: self.create_disposition,
            create_options: self.create_options,
            impersonation_level: self.impersonation_level,
            security_flags: self.security_flags,
        };
        Ok(body(&write_words(&words)?, &area.finish()))
    }

    /// Decodes an `NT_CREATE_ANDX` request.
    pub fn decode(message: &Message) -> Result<Self, WireError> {
        message.expect_words(command::NT_CREATE_ANDX, &[CREATE_REQUEST_WORDS], "24")?;
        let words: CreateRequestWords = read_words(message.words())?;
        let area = message.block(
            "ByteCount",
            message.byte_area_offset(),
            usize::from(message.byte_count()),
        )?;
        let name = area
            .get(1..1 + usize::from(words.name_length))
            .ok_or(WireError::Truncated {
                part: "Name",
                declared: 1 + usize::from(words.name_length),
                length: area.len(),
            })?;

        Ok(Self {
            flags: words.flags,
            root_directory_fid: words.root_directory_fid,
            desired_access: words.desired_access,
            allocation_size: words.allocation_size,
            ext_file_attributes: words.ext_file_attributes,
            share_access: words.share_access,
            create_disposition: words.create_disposition,
            create_options: words.create_options,
            impersonation_level: words.impersonation_level,
            security_flags: words.security_flags,
            name: from_utf16("Name", 0, name)?,
        })
    }
}

/// An `NT_CREATE_ANDX` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtCreateAndxResponse {
    /// The AndX prologue as it arrived.
    pub andx: AndX,
    /// The oplock the server granted.
    pub oplock_level: u8,
    /// The handle.
    pub fid: u16,
    /// What the server did: opened, created, overwrote.
    pub create_action: u32,
    /// Creation time, in Windows FILETIME units.
    pub creation_time: i64,
    /// Last access time.
    pub last_access_time: i64,
    /// Last write time.
    pub last_write_time: i64,
    /// Last metadata change time.
    pub change_time: i64,
    /// The file's attributes.
    pub ext_file_attributes: u32,
    /// Space allocated to the file.
    pub allocation_size: u64,
    /// The file's length.
    pub end_of_file: u64,
    /// Disk file, pipe, or device.
    pub resource_type: u16,
    /// Pipe state, where the resource is a pipe.
    pub nm_pipe_status: u16,
    /// Whether the thing opened is a directory.
    pub directory: u8,
}

impl NtCreateAndxResponse {
    /// Decodes an `NT_CREATE_ANDX` response.
    pub fn decode(message: &Message) -> Result<Self, WireError> {
        message.expect_words(command::NT_CREATE_ANDX, &[CREATE_RESPONSE_WORDS], "34")?;
        let words: CreateResponseWords = read_words(message.words())?;
        words.andx.refuse_chaining()?;
        Ok(Self {
            andx: words.andx,
            oplock_level: words.oplock_level,
            fid: words.fid,
            create_action: words.create_action,
            creation_time: words.creation_time,
            last_access_time: words.last_access_time,
            last_write_time: words.last_write_time,
            change_time: words.change_time,
            ext_file_attributes: words.ext_file_attributes,
            allocation_size: words.allocation_size,
            end_of_file: words.end_of_file,
            resource_type: words.resource_type,
            nm_pipe_status: words.nm_pipe_status,
            directory: words.directory,
        })
    }

    /// Encodes the command body. The byte area is empty.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        let words = CreateResponseWords {
            andx: self.andx,
            oplock_level: self.oplock_level,
            fid: self.fid,
            create_action: self.create_action,
            creation_time: self.creation_time,
            last_access_time: self.last_access_time,
            last_write_time: self.last_write_time,
            change_time: self.change_time,
            ext_file_attributes: self.ext_file_attributes,
            allocation_size: self.allocation_size,
            end_of_file: self.end_of_file,
            resource_type: self.resource_type,
            nm_pipe_status: self.nm_pipe_status,
            directory: self.directory,
        };
        Ok(body(&write_words(&words)?, &[]))
    }
}

/// An `SMB_COM_CLOSE` request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseRequest {
    /// The handle to release.
    pub fid: u16,
    /// A last-write time to stamp, or `0xFFFFFFFF` to leave it alone.
    pub last_time_modified: u32,
}

impl CloseRequest {
    /// Encodes the command body.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        let words = CloseRequestWords {
            fid: self.fid,
            last_time_modified: self.last_time_modified,
        };
        Ok(body(&write_words(&words)?, &[]))
    }

    /// Decodes a close request.
    pub fn decode(message: &Message) -> Result<Self, WireError> {
        message.expect_words(command::CLOSE, &[CLOSE_REQUEST_WORDS], "3")?;
        let words: CloseRequestWords = read_words(message.words())?;
        Ok(Self {
            fid: words.fid,
            last_time_modified: words.last_time_modified,
        })
    }
}

/// A close response, which carries nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CloseResponse;

impl CloseResponse {
    /// Decodes a close response.
    ///
    /// Zero words is this command's successful shape, not the error shape.
    pub fn decode(message: &Message) -> Result<Self, WireError> {
        message.expect_words(command::CLOSE, &[0], "0")?;
        Ok(Self)
    }

    /// Encodes the command body.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        Ok(body(&[], &[]))
    }
}

/// An `SMB_COM_RENAME` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameRequest {
    /// Which attributes a matching file may carry.
    pub search_attributes: u16,
    /// The path being renamed.
    pub old_name: String,
    /// The path it becomes.
    pub new_name: String,
}

impl RenameRequest {
    /// Encodes the command body.
    ///
    /// Two names, and only the second is padded. The byte area begins at 37, so
    /// the first `0x04` already lands the old name on 38; after an even-length
    /// name and its two-byte terminator the second `0x04` lands on an even
    /// offset, which is what makes the pad necessary there and only there.
    /// Padding the old name as well shifts every character of it.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        let mut area = ByteArea::for_word_count(usize::from(RENAME_REQUEST_WORDS));

        area.put(&[BUFFER_FORMAT_ASCII]);
        require_word_aligned("OldFileName", area.offset())?;
        area.put(&utf16z(&self.old_name));

        area.put(&[BUFFER_FORMAT_ASCII]);
        area.align_to(2);
        require_word_aligned("NewFileName", area.offset())?;
        area.put(&utf16z(&self.new_name));

        let words = RenameRequestWords {
            search_attributes: self.search_attributes,
        };
        Ok(body(&write_words(&words)?, &area.finish()))
    }

    /// Decodes a rename request.
    pub fn decode(message: &Message) -> Result<Self, WireError> {
        message.expect_words(command::RENAME, &[RENAME_REQUEST_WORDS], "1")?;
        let words: RenameRequestWords = read_words(message.words())?;
        let area = message.block(
            "ByteCount",
            message.byte_area_offset(),
            usize::from(message.byte_count()),
        )?;

        let old = utf16_field("OldFileName", area, 1)?;
        let mut second = 1 + old.1 + 2;
        if area.get(second) != Some(&BUFFER_FORMAT_ASCII) {
            return Err(WireError::Truncated {
                part: "NewFileName marker",
                declared: second + 1,
                length: area.len(),
            });
        }
        second += 1;
        if !(message.byte_area_offset() + second).is_multiple_of(2) {
            second += 1;
        }
        let new = utf16_field("NewFileName", area, second)?;

        Ok(Self {
            search_attributes: words.search_attributes,
            old_name: old.0,
            new_name: new.0,
        })
    }
}

/// Reads a null-terminated UTF-16LE string at `start`, returning it and its
/// length in bytes without the terminator.
fn utf16_field(
    field: &'static str,
    area: &[u8],
    start: usize,
) -> Result<(String, usize), WireError> {
    let rest = area.get(start..).ok_or(WireError::Truncated {
        part: field,
        declared: start,
        length: area.len(),
    })?;
    let end = rest
        .as_chunks::<2>()
        .0
        .iter()
        .position(|pair| pair == &[0, 0])
        .map(|units| units * 2)
        .ok_or(WireError::Truncated {
            part: field,
            declared: rest.len(),
            length: rest.len(),
        })?;
    Ok((from_utf16(field, 0, &rest[..end])?, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::header::SmbHeader;
    use crate::wire::message;

    /// The rename byte area, which has no committed fixture. The shape asserted
    /// is the reference's: `0x04`, the old name, its terminator, `0x04`, one
    /// pad byte, the new name, its terminator.
    #[test]
    fn rename_pads_the_second_name_and_not_the_first() {
        let request = RenameRequest {
            search_attributes: 0x0016,
            old_name: "ab".to_owned(),
            new_name: "cd".to_owned(),
        };
        let encoded = request.encode_body().unwrap();
        let area = &encoded[1 + 2 + 2..];

        assert_eq!(ByteArea::for_word_count(1).offset(), 37);
        assert_eq!(
            area,
            &[
                BUFFER_FORMAT_ASCII,
                b'a',
                0,
                b'b',
                0,
                0,
                0,
                BUFFER_FORMAT_ASCII,
                0,
                b'c',
                0,
                b'd',
                0,
                0,
                0,
            ]
        );

        let raw = message(&SmbHeader::request(command::RENAME), &encoded).unwrap();
        let parsed = Message::parse(raw).unwrap();
        assert_eq!(RenameRequest::decode(&parsed).unwrap(), request);
    }

    /// The same shape with longer names, which is what the decode side has to
    /// find its way through.
    #[test]
    fn rename_round_trips_longer_names() {
        let request = RenameRequest {
            search_attributes: 0,
            old_name: "abc".to_owned(),
            new_name: "de".to_owned(),
        };
        let encoded = request.encode_body().unwrap();
        let raw = message(&SmbHeader::request(command::RENAME), &encoded).unwrap();
        let parsed = Message::parse(raw).unwrap();
        assert_eq!(RenameRequest::decode(&parsed).unwrap(), request);
    }
}
