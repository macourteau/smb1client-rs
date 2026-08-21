//! The absolute-offset sites, and the helper that back-patches them.
//!
//! SMB1 carries absolute offsets in four places, in two shapes. `TRANS2` and
//! `SMB_COM_TRANSACTION` both declare `ParameterOffset` and `DataOffset`
//! computed from the start of the SMB message; `WRITE_ANDX` and `READ_ANDX`
//! each declare a `DataOffset` the same way, written on encode and honoured on
//! decode. A `binrw` derive cannot express any of them, because the value a
//! field carries depends on where in the message the block it points at ends up.
//!
//! [`ByteArea`] is what serves all four. It appends blocks to a command's byte
//! area while tracking where each one lands relative to the start of the SMB
//! header, so an encoder asks for the offset rather than computing it.
//!
//! **Alignment is a separate mechanism and this helper does not infer it.** The
//! pad between the header, the parameter block and the data block is a property
//! of the command being encoded — pinned here against fixture bytes, since
//! getting it wrong moves every offset with it. The 2-byte boundary a UTF-16
//! name in a byte area has to begin on is not block padding at all: each
//! command reaches it its own way, and [`require_word_aligned`] is the check
//! that it did, not a computation of how.

use super::WireError;
use super::header::HEADER_LEN;

/// A command's byte area under construction, tracking each block's offset from
/// the start of the SMB message.
#[derive(Debug)]
pub struct ByteArea {
    start: usize,
    bytes: Vec<u8>,
}

impl ByteArea {
    /// A byte area for a command whose word block holds `word_count` words.
    ///
    /// The area begins after the header, the `WordCount` byte, the words and
    /// the two-byte `ByteCount`.
    pub fn for_word_count(word_count: usize) -> Self {
        Self::at(HEADER_LEN + 1 + word_count * 2 + 2)
    }

    /// A byte area beginning at `start` bytes from the start of the SMB message.
    pub fn at(start: usize) -> Self {
        Self {
            start,
            bytes: Vec::new(),
        }
    }

    /// Where the next byte appended will land, measured from the start of the
    /// SMB message. This is the value an absolute-offset field carries.
    pub fn offset(&self) -> usize {
        self.start + self.bytes.len()
    }

    /// The length of the area so far, which is what `ByteCount` declares.
    ///
    /// `ByteCount` is 16 bits and wraps. It is declared from this and is never
    /// read back as a length.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Pads with zeroes until [`ByteArea::offset`] is a multiple of `align`.
    pub fn align_to(&mut self, align: usize) {
        debug_assert!(align.is_power_of_two());
        while !self.offset().is_multiple_of(align) {
            self.bytes.push(0);
        }
    }

    /// Appends a block, returning the offset it starts at.
    pub fn put(&mut self, block: &[u8]) -> usize {
        let offset = self.offset();
        self.bytes.extend_from_slice(block);
        offset
    }

    /// Pads to `align`, then appends a block, returning the offset it starts at.
    pub fn put_aligned(&mut self, align: usize, block: &[u8]) -> usize {
        self.align_to(align);
        self.put(block)
    }

    /// The finished byte area.
    pub fn finish(self) -> Vec<u8> {
        self.bytes
    }
}

/// The boundary a UTF-16 name in a byte area has to begin on, measured from the
/// start of the SMB header.
pub const NAME_ALIGNMENT: usize = 2;

/// Refuses a name that would not begin on a 2-byte boundary.
///
/// Three commands carry this problem and no two solve it the same way —
/// `NT_CREATE_ANDX` pads, `TREE_CONNECT_ANDX` declares a one-byte password, and
/// `SMB_COM_RENAME` pads its second name and not its first. Each does its own
/// thing and then calls this, because omitting the alignment or adding one
/// where the reference adds none shifts every character of the name by a byte
/// and produces a frame the server cannot parse.
pub fn require_word_aligned(field: &'static str, offset: usize) -> Result<(), WireError> {
    if offset.is_multiple_of(NAME_ALIGNMENT) {
        Ok(())
    } else {
        Err(WireError::MisalignedName { field, offset })
    }
}

/// Reads an absolute offset a server declared, returning the block it points at.
///
/// The bound is the message, never `ByteCount`: a 16-bit count wraps, and a
/// server may pad past the end of the block it declared.
pub fn block_at<'a>(
    message: &'a [u8],
    field: &'static str,
    offset: usize,
    length: usize,
) -> Result<&'a [u8], WireError> {
    message
        .get(offset..)
        .and_then(|rest| rest.get(..length))
        .ok_or(WireError::BlockOutOfRange {
            field,
            offset,
            length,
            message_length: message.len(),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The `TRANS2` request shape, pinned against `capture/0009-c2s-cmd32.bin`:
    /// `WordCount = 15`, a byte area beginning at 65, one pad byte, and a
    /// parameter block at 66. Two bytes of alignment, not four — a
    /// four-byte-aligned parameter block would land on 68 and move every offset
    /// after it.
    #[test]
    fn trans2_request_parameter_block_lands_on_sixty_six() {
        let mut area = ByteArea::for_word_count(15);
        assert_eq!(area.offset(), 65);
        let parameter_offset = area.put_aligned(2, &[0u8; 18]);
        assert_eq!(parameter_offset, 66);
        // With no data the reference still declares a `DataOffset`, and it is
        // the end of the parameter block.
        let data_offset = area.put_aligned(2, &[]);
        assert_eq!(data_offset, 84);
        assert_eq!(area.len(), 19);
        assert_eq!(area.finish()[0], 0);
    }

    /// The `WRITE_ANDX` shape, pinned against
    /// `capture-large/0027-c2s-cmd2f.bin` and `capture-trans/0019-c2s-cmd2f.bin`:
    /// `WordCount = 14`, a byte area beginning at 63, and a payload that starts
    /// there with no pad at all. Payload bytes are not a name and take no
    /// alignment.
    #[test]
    fn write_andx_payload_starts_at_the_byte_area() {
        let mut area = ByteArea::for_word_count(14);
        assert_eq!(area.offset(), 63);
        assert_eq!(area.put(&[0u8; 116]), 63);
        assert_eq!(area.len(), 116);
    }

    /// The `SMB_COM_TRANSACTION` shape, pinned against
    /// `capture-trans/0009-c2s-cmd25.bin`: two setup words put the byte area at
    /// 67, the 13-byte name goes in ahead of everything, and the parameter
    /// block lands on 80 with no padding needed there.
    #[test]
    fn transaction_offsets_follow_the_name() {
        let mut area = ByteArea::for_word_count(16);
        assert_eq!(area.offset(), 67);
        area.put(b"\\PIPE\\LANMAN\0");
        assert_eq!(area.offset(), 80);
        let parameter_offset = area.put_aligned(2, &[0u8; 19]);
        assert_eq!(parameter_offset, 80);
        // The 19-byte parameter block ends odd, so one pad byte follows it and
        // the `DataOffset` beside it is 100 even with no data to put there.
        area.align_to(2);
        assert_eq!(area.offset(), 100);
        assert_eq!(area.len(), 33);
    }

    #[test]
    fn name_alignment_is_checked_and_not_computed() {
        assert!(require_word_aligned("Path", 44).is_ok());
        assert!(matches!(
            require_word_aligned("Path", 43),
            Err(WireError::MisalignedName {
                field: "Path",
                offset: 43
            })
        ));
    }

    #[test]
    fn a_declared_offset_past_the_message_is_refused() {
        let message = [0u8; 64];
        assert_eq!(block_at(&message, "DataOffset", 60, 4).unwrap().len(), 4);
        assert!(matches!(
            block_at(&message, "DataOffset", 60, 5),
            Err(WireError::BlockOutOfRange { .. })
        ));
        assert!(matches!(
            block_at(&message, "DataOffset", 65, 0),
            Err(WireError::BlockOutOfRange { .. })
        ));
    }
}
