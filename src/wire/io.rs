//! `SMB_COM_READ_ANDX` and `SMB_COM_WRITE_ANDX`.
//!
//! These two are why `ByteCount` must never be used as a length. A
//! 130,048-byte write carries `ByteCount = 64512` beside `DataLengthHigh = 1`,
//! and the read reply that brings it back carries `ByteCount = 64513`. A derive
//! written the obvious way — `#[br(count = byte_count)]` — yields 64,513 of
//! 130,048 bytes, a silent short read.
//!
//! The lengths come from the fields that carry them at full width instead:
//! `DataLength | DataLengthHigh << 16` says how many bytes there are, and
//! `DataOffset` says where in the message they start. The NetBIOS frame length
//! bounds the message and is what the offset is checked against — but it is not
//! the length rule either, since deriving the payload length from the frame
//! silently absorbs whatever trailing padding a server appends.

use binrw::binrw;

use super::andx::AndX;
use super::header::command;
use super::{Message, WireError, body, offsets, read_words, write_words};

/// The `WordCount` of a `READ_ANDX` request and of its response.
const READ_WORDS: u8 = 12;

/// The `WordCount` of a `WRITE_ANDX` request.
const WRITE_REQUEST_WORDS: u8 = 14;

/// The `WordCount` of a `WRITE_ANDX` response.
const WRITE_RESPONSE_WORDS: u8 = 6;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReadRequestWords {
    andx: AndX,
    fid: u16,
    offset: u32,
    max_count: u16,
    min_count: u16,
    /// A timeout on a pipe read, and the high 16 bits of the byte count on a
    /// file read under `CAP_LARGE_READX`.
    max_count_high: u32,
    remaining: u16,
    offset_high: u32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ReadResponseWords {
    andx: AndX,
    available: u16,
    data_compaction_mode: u16,
    reserved: u16,
    data_length: u16,
    data_offset: u16,
    data_length_high: u16,
    reserved2: [u16; 4],
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WriteRequestWords {
    andx: AndX,
    fid: u16,
    offset: u32,
    timeout: u32,
    write_mode: u16,
    remaining: u16,
    data_length_high: u16,
    data_length: u16,
    data_offset: u16,
    offset_high: u32,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WriteResponseWords {
    andx: AndX,
    count: u16,
    remaining: u16,
    count_high: u16,
    reserved: u16,
}

/// A `READ_ANDX` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadAndxRequest {
    /// The file or pipe to read.
    pub fid: u16,
    /// Where in the file to read from.
    pub offset: u64,
    /// How many bytes to ask for. Split across two fields on the wire, the high
    /// half being meaningful only under `CAP_LARGE_READX`.
    pub max_count: u32,
    /// The fewest bytes the reply may carry.
    pub min_count: u16,
    /// A hint at how much more the client intends to read.
    pub remaining: u16,
}

impl ReadAndxRequest {
    /// Encodes the command body. The byte area is empty.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        let words = ReadRequestWords {
            andx: AndX::NONE,
            fid: self.fid,
            offset: self.offset as u32,
            max_count: self.max_count as u16,
            min_count: self.min_count,
            max_count_high: self.max_count >> 16,
            remaining: self.remaining,
            offset_high: (self.offset >> 32) as u32,
        };
        Ok(body(&write_words(&words)?, &[]))
    }

    /// Decodes a `READ_ANDX` request.
    pub fn decode(message: &Message) -> Result<Self, WireError> {
        message.expect_words(command::READ_ANDX, &[READ_WORDS], "12")?;
        let words: ReadRequestWords = read_words(message.words())?;
        Ok(Self {
            fid: words.fid,
            offset: u64::from(words.offset) | (u64::from(words.offset_high) << 32),
            max_count: u32::from(words.max_count) | (words.max_count_high << 16),
            min_count: words.min_count,
            remaining: words.remaining,
        })
    }
}

/// A `READ_ANDX` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadAndxResponse {
    /// The AndX prologue as it arrived.
    pub andx: AndX,
    /// Bytes remaining to be read from a pipe, or `0xFFFF` from a file.
    pub available: u16,
    /// Compaction mode. Always zero in practice.
    pub data_compaction_mode: u16,
    /// The offset the payload was found at, kept so a reply can be re-encoded
    /// byte for byte.
    pub data_offset: u16,
    /// The payload.
    pub data: Vec<u8>,
}

impl ReadAndxResponse {
    /// Decodes a `READ_ANDX` response.
    ///
    /// The payload length is `DataLength | DataLengthHigh << 16`. `ByteCount`
    /// is not consulted.
    pub fn decode(message: &Message) -> Result<Self, WireError> {
        message.expect_words(command::READ_ANDX, &[READ_WORDS], "12")?;
        let words: ReadResponseWords = read_words(message.words())?;
        words.andx.refuse_chaining()?;

        let length = usize::from(words.data_length) | (usize::from(words.data_length_high) << 16);
        let data = message
            .block("DataOffset", usize::from(words.data_offset), length)?
            .to_vec();

        Ok(Self {
            andx: words.andx,
            available: words.available,
            data_compaction_mode: words.data_compaction_mode,
            data_offset: words.data_offset,
            data,
        })
    }

    /// Encodes the command body, placing the payload at the offset the struct
    /// carries.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        let mut area = offsets::ByteArea::for_word_count(usize::from(READ_WORDS));
        while area.offset() < usize::from(self.data_offset) {
            area.put(&[0]);
        }
        area.put(&self.data);

        let words = ReadResponseWords {
            andx: self.andx,
            available: self.available,
            data_compaction_mode: self.data_compaction_mode,
            reserved: 0,
            data_length: self.data.len() as u16,
            data_offset: self.data_offset,
            data_length_high: (self.data.len() >> 16) as u16,
            reserved2: [0; 4],
        };
        Ok(body(&write_words(&words)?, &area.finish()))
    }
}

/// A `WRITE_ANDX` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteAndxRequest {
    /// The file or pipe to write.
    pub fid: u16,
    /// Where in the file to write.
    pub offset: u64,
    /// Write-through and message-mode bits.
    pub write_mode: u16,
    /// A hint at how much more the client intends to write.
    pub remaining: u16,
    /// The payload.
    pub data: Vec<u8>,
}

impl WriteAndxRequest {
    /// Encodes the command body.
    ///
    /// The payload starts at the byte area with no padding: it is not a name
    /// and takes no alignment.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        let mut area = offsets::ByteArea::for_word_count(usize::from(WRITE_REQUEST_WORDS));
        let data_offset = area.put(&self.data);

        let words = WriteRequestWords {
            andx: AndX::NONE,
            fid: self.fid,
            offset: self.offset as u32,
            timeout: 0,
            write_mode: self.write_mode,
            remaining: self.remaining,
            data_length_high: (self.data.len() >> 16) as u16,
            data_length: self.data.len() as u16,
            data_offset: data_offset as u16,
            offset_high: (self.offset >> 32) as u32,
        };
        Ok(body(&write_words(&words)?, &area.finish()))
    }

    /// Decodes a `WRITE_ANDX` request.
    pub fn decode(message: &Message) -> Result<Self, WireError> {
        message.expect_words(command::WRITE_ANDX, &[WRITE_REQUEST_WORDS], "14")?;
        let words: WriteRequestWords = read_words(message.words())?;
        let length = usize::from(words.data_length) | (usize::from(words.data_length_high) << 16);
        Ok(Self {
            fid: words.fid,
            offset: u64::from(words.offset) | (u64::from(words.offset_high) << 32),
            write_mode: words.write_mode,
            remaining: words.remaining,
            data: message
                .block("DataOffset", usize::from(words.data_offset), length)?
                .to_vec(),
        })
    }
}

/// A `WRITE_ANDX` response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriteAndxResponse {
    /// The AndX prologue as it arrived.
    pub andx: AndX,
    /// How many bytes the server wrote, at full width.
    pub count: u32,
    /// How much of the client's declared remainder the server expects.
    pub remaining: u16,
}

impl WriteAndxResponse {
    /// Decodes a `WRITE_ANDX` response.
    pub fn decode(message: &Message) -> Result<Self, WireError> {
        message.expect_words(command::WRITE_ANDX, &[WRITE_RESPONSE_WORDS], "6")?;
        let words: WriteResponseWords = read_words(message.words())?;
        words.andx.refuse_chaining()?;
        Ok(Self {
            andx: words.andx,
            count: u32::from(words.count) | (u32::from(words.count_high) << 16),
            remaining: words.remaining,
        })
    }

    /// Encodes the command body. The byte area is empty.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        let words = WriteResponseWords {
            andx: self.andx,
            count: self.count as u16,
            remaining: self.remaining,
            count_high: (self.count >> 16) as u16,
            reserved: 0,
        };
        Ok(body(&write_words(&words)?, &[]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::header::SmbHeader;
    use crate::wire::message;

    /// The frames that establish this were measured against a live Samba
    /// container and are in no committed capture, so what stands in for them is
    /// a message built here to the same shape: 130,048 payload bytes under a
    /// `ByteCount` of 64,513. A decoder that trusts `ByteCount` returns 64,513
    /// bytes and looks like it worked.
    #[test]
    fn a_read_reply_past_sixty_five_kilobytes_is_not_bounded_by_byte_count() {
        let payload: Vec<u8> = (0..130_048u32).map(|index| index as u8).collect();
        let reply = ReadAndxResponse {
            andx: AndX::NONE,
            available: 0xFFFF,
            data_compaction_mode: 0,
            data_offset: 60,
            data: payload.clone(),
        };
        let encoded = reply.encode_body().unwrap();
        let raw = message(&SmbHeader::request(command::READ_ANDX), &encoded).unwrap();

        let parsed = Message::parse(raw).unwrap();
        assert_eq!(parsed.byte_count(), 64_513);
        let decoded = ReadAndxResponse::decode(&parsed).unwrap();
        assert_eq!(decoded.data.len(), 130_048);
        assert_eq!(decoded.data, payload);
    }

    /// The write side of the same wrap. `ByteCount` truncates to 64,512 and
    /// `DataLengthHigh` is what carries the missing bit.
    #[test]
    fn a_large_write_declares_its_length_in_two_fields() {
        let request = WriteAndxRequest {
            fid: 0xCB69,
            offset: 0,
            write_mode: 0,
            remaining: 0,
            data: vec![0xAB; 130_048],
        };
        let encoded = request.encode_body().unwrap();
        let words: WriteRequestWords = read_words(&encoded[1..1 + 28]).unwrap();
        assert_eq!(words.data_length, 64_512);
        assert_eq!(words.data_length_high, 1);
        assert_eq!(words.data_offset, 63);

        let byte_count = u16::from_le_bytes([encoded[29], encoded[30]]);
        assert_eq!(byte_count, 64_512);

        let raw = message(&SmbHeader::request(command::WRITE_ANDX), &encoded).unwrap();
        let parsed = Message::parse(raw).unwrap();
        assert_eq!(WriteAndxRequest::decode(&parsed).unwrap(), request);
    }

    /// A file offset past 4 GiB travels in two fields as well.
    #[test]
    fn offsets_past_four_gigabytes_split_across_two_fields() {
        let request = ReadAndxRequest {
            fid: 1,
            offset: 0x0000_0003_1234_5678,
            max_count: 130_048,
            min_count: 0,
            remaining: 0,
        };
        let encoded = request.encode_body().unwrap();
        let raw = message(&SmbHeader::request(command::READ_ANDX), &encoded).unwrap();
        let parsed = Message::parse(raw).unwrap();
        assert_eq!(ReadAndxRequest::decode(&parsed).unwrap(), request);
    }
}
