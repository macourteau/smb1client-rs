//! Message encode and decode.
//!
//! This layer is the codec and nothing above it: it turns bytes into typed
//! messages and typed messages into bytes, and holds no connection state, no
//! retry policy and no status classification. Two rules run through all of it
//! and are worth stating once.
//!
//! **`ByteCount` is 16 bits, it wraps, and it is never used as a length.** A
//! 130,048-byte read reply carries `ByteCount = 64513`, so a decoder that
//! trusts it returns 64,513 of 130,048 bytes: a silent short read. Lengths come
//! from the fields that carry them at full width — the NetBIOS frame length
//! bounds the message, and a command's own count fields locate the payload
//! inside it. The frame length alone is not the rule either, since deriving a
//! payload length from it absorbs whatever trailing padding a server appends.
//!
//! **A response's shape is keyed off `WordCount`, never off its status.** SMB1
//! usually answers a failed command with `WordCount = 0` and an empty byte area
//! rather than a zeroed version of that command's successful response, so a
//! derive that reads a command's words unconditionally fails on those frames.
//! Reading that as universal breaks authentication in the other direction:
//! `STATUS_MORE_PROCESSING_REQUIRED` sits inside the error class and carries
//! four words and a 297-byte byte area, because that frame is the NTLM
//! challenge. So the decoders here branch on the `WordCount` the frame actually
//! carries and leave the status to the layer that classifies statuses.

// The connection actor is command-agnostic: it frames, routes and reassembles,
// and the body it carries is opaque to it. So what it brings into use is the
// header, the NetBIOS framing and the transaction response — and the encoders
// and per-command decoders below stay unreachable until the layer that issues
// each command exists. The allow is per module rather than over the whole
// layer, so it shrinks as each build step lands rather than hiding what the
// step after it leaves behind.
//
// What remains dead once the filesystem verbs exist is the *decode* side of the
// commands this crate only sends: it has one consumer, the fixture round-trip,
// and that is `#[cfg(test)]`. Dropping it would cost the corpus sweep the
// coverage it exists for.
pub mod andx;
/// `SMB_COM_ECHO`, issued by the connection cache's liveness probe and by
/// nothing else.
pub mod echo;
/// `NT_CREATE_ANDX`, `SMB_COM_CLOSE` and `SMB_COM_RENAME`, issued by `tree.rs`
/// and `resource/`.
#[allow(dead_code)]
pub mod file;
/// `TRANS2_FIND_FIRST2` and `TRANS2_FIND_NEXT2`, issued by the listing
/// iterator.
#[allow(dead_code)]
pub mod find;
pub mod header;
/// The TRANS2 information subcommands, issued by `tree.rs` and `resource/`.
pub mod info;
/// `READ_ANDX` and `WRITE_ANDX`, issued by `resource/`.
#[allow(dead_code)]
pub mod io;
/// `SMB_COM_NEGOTIATE`, issued by the handshake.
pub mod negotiate;
pub mod netbios;
pub mod offsets;
/// `SESSION_SETUP_ANDX` and `LOGOFF_ANDX`. The setup is issued by the
/// handshake; the logoff by the teardown, which arrives with the caching layer.
#[allow(dead_code)]
pub mod session;
pub mod trace;
/// The response side is what the actor reassembles; the request side is built
/// by the layers that issue transactions, at build steps 4 and 5.
#[allow(dead_code)]
pub mod transaction;
/// `TREE_CONNECT_ANDX` and `SMB_COM_TREE_DISCONNECT`, issued by `tree.rs`.
#[allow(dead_code)]
pub mod tree;

#[cfg(test)]
mod fixtures;

#[cfg(test)]
mod fscc_cross_check;

use binrw::BinRead;
use binrw::io::Cursor;

use crate::status::NtStatus;
use header::{HEADER_LEN, SmbHeader};

/// What can go wrong turning bytes into messages, or messages into bytes.
///
/// Which of these fail the connection and which fail one request is decided
/// above this layer; the wire layer's job is to name what it saw.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// A NetBIOS message type this crate does not recognise. After one, the
    /// reader cannot tell where the next message begins.
    #[error("unrecognised NetBIOS message type {0:#04x}")]
    UnknownNetbiosType(u8),

    /// The NetBIOS length's seven reserved bits were not zero.
    ///
    /// The length is read as 17 bits, which bounds an inbound frame at 131,071
    /// bytes. Reading the other seven as length would raise that to 16,777,215
    /// for no message this crate sends or expects.
    #[error("NetBIOS length byte {0:#04x} sets a reserved bit")]
    ReservedNetbiosBits(u8),

    /// A message longer than the 17-bit NetBIOS length can describe.
    #[error("SMB message of {0} bytes exceeds the NetBIOS frame limit")]
    MessageTooLong(usize),

    /// The message did not begin with `\xffSMB`, or ended inside a field.
    #[error("malformed SMB message: {0}")]
    Malformed(#[from] binrw::Error),

    /// The message ended before its declared word block or `ByteCount`.
    #[error(
        "SMB message of {length} bytes is shorter than its declared {declared} bytes of {part}"
    )]
    Truncated {
        /// Which part of the message ran out.
        part: &'static str,
        /// The length declared for it.
        declared: usize,
        /// The bytes the message actually holds.
        length: usize,
    },

    /// A response arrived for a command other than the one being decoded.
    #[error("expected command {expected:#04x}, message carries {actual:#04x}")]
    UnexpectedCommand {
        /// The command the decoder was built for.
        expected: u8,
        /// The command the header names.
        actual: u8,
    },

    /// The frame carries no command body at all: `WordCount = 0` and an empty
    /// byte area, which is how SMB1 usually answers a failed command.
    #[error("command {command:#04x} answered {status} with no words")]
    NoResponseBody {
        /// The command whose response this is.
        command: u8,
        /// The status the header carries, which is the whole of what it says.
        status: NtStatus,
    },

    /// A `WordCount` this crate does not parse for that command.
    #[error("command {command:#04x} carries {actual} words, expected {expected}")]
    UnexpectedWordCount {
        /// The command whose response this is.
        command: u8,
        /// The count the frame carries.
        actual: u8,
        /// What the decoder parses.
        expected: &'static str,
    },

    /// A response chained another command. This crate chains nothing and can
    /// follow nothing.
    #[error("response chains command {0:#04x}")]
    ChainedCommand(u8),

    /// An absolute offset a server declared points outside the message.
    #[error("{field} = {offset} with {length} bytes falls outside a {message_length}-byte message")]
    BlockOutOfRange {
        /// The field that declared it.
        field: &'static str,
        /// The offset it declared.
        offset: usize,
        /// The length expected at it.
        length: usize,
        /// The message the offset was read against.
        message_length: usize,
    },

    /// A name would not have begun on a 2-byte boundary.
    #[error("{field} would begin at offset {offset}, which is not word-aligned")]
    MisalignedName {
        /// The field being placed.
        field: &'static str,
        /// Where it would have landed.
        offset: usize,
    },

    /// The server accepted no dialect this crate offered.
    #[error("server accepted none of the dialects offered")]
    NoCommonDialect,

    /// The server selected a dialect that was not offered.
    #[error("server selected dialect index {0}, which was not offered")]
    UnsupportedDialectIndex(u16),

    /// A directory entry's `NextEntryOffset` is below the minimum entry size,
    /// so honouring it would re-parse overlapping bytes into fabricated
    /// entries.
    #[error(
        "directory entry at {offset} declares NextEntryOffset {next}, below the {minimum}-byte minimum"
    )]
    EntryOffsetTooSmall {
        /// Where the entry begins in the data buffer.
        offset: usize,
        /// The offset it declared.
        next: usize,
        /// The smallest an entry can be.
        minimum: usize,
    },

    /// The entry chain and the reply's own `SearchCount` disagree.
    ///
    /// The chain and the count are two statements about the same reply, and a
    /// reply that disagrees with itself is the same class of defect as a chain
    /// that ends short.
    #[error("walked {walked} directory entries, reply reports SearchCount = {search_count}")]
    EntryCountMismatch {
        /// What the chain walk found.
        walked: usize,
        /// What the reply says it returned.
        search_count: u16,
    },

    /// A filename that is not valid UTF-16.
    ///
    /// The entry is not handed back with a lossily decoded name: paths here are
    /// `str`-shaped, so a lossy name produces an entry that looks usable and
    /// fails when the caller acts on it.
    #[error("{field} at directory position {position} is not valid UTF-16: {bytes:02x?}")]
    InvalidUtf16 {
        /// The field the name came from.
        field: &'static str,
        /// The entry's position in the directory.
        position: usize,
        /// The raw bytes, so a caller can see what actually arrived.
        bytes: Vec<u8>,
    },

    /// A string this crate is asked to send does not fit the field that carries
    /// it.
    #[error("{field} of {length} bytes exceeds the {limit} bytes the field carries")]
    FieldTooLong {
        /// The field being written.
        field: &'static str,
        /// The length asked for.
        length: usize,
        /// What it can carry.
        limit: usize,
    },
}

/// One complete SMB1 message: the header, the word block and the byte area.
///
/// The byte area is bounded by the message the NetBIOS frame delivered, not by
/// `ByteCount`. `ByteCount` is read and reported, and every payload length
/// comes from a command's own full-width count fields instead.
#[derive(Debug, Clone)]
pub struct Message {
    header: SmbHeader,
    bytes: Vec<u8>,
    word_count: u8,
    byte_count: u16,
}

impl Message {
    /// Parses one SMB message. `bytes` is the message the NetBIOS frame
    /// delivered, its own four-byte header already stripped.
    pub fn parse(bytes: Vec<u8>) -> Result<Self, WireError> {
        let mut cursor = Cursor::new(&bytes);
        let header = SmbHeader::read(&mut cursor)?;

        let word_count = *bytes.get(HEADER_LEN).ok_or(WireError::Truncated {
            part: "WordCount",
            declared: HEADER_LEN + 1,
            length: bytes.len(),
        })?;

        let byte_count_at = HEADER_LEN + 1 + usize::from(word_count) * 2;
        let byte_count = bytes
            .get(byte_count_at..byte_count_at + 2)
            .map(|raw| u16::from_le_bytes([raw[0], raw[1]]))
            .ok_or(WireError::Truncated {
                part: "words",
                declared: byte_count_at + 2,
                length: bytes.len(),
            })?;

        Ok(Self {
            header,
            bytes,
            word_count,
            byte_count,
        })
    }

    /// The message's header.
    pub fn header(&self) -> &SmbHeader {
        &self.header
    }

    /// The whole SMB message. Absolute offsets are measured against this.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The declared `WordCount`, which is what a response's shape is keyed off.
    pub fn word_count(&self) -> u8 {
        self.word_count
    }

    /// The word block.
    pub fn words(&self) -> &[u8] {
        let start = HEADER_LEN + 1;
        &self.bytes[start..start + usize::from(self.word_count) * 2]
    }

    /// The declared `ByteCount`.
    ///
    /// It is 16 bits and it wraps. Read it to report it; never use it as a
    /// length.
    pub fn byte_count(&self) -> u16 {
        self.byte_count
    }

    /// The byte area's length, bounded by what the frame actually holds.
    ///
    /// **Not `byte_count()`.** That field is 16 bits and wraps, and the rule
    /// this module opens with is that it is never used as a length. No command
    /// decoded here can carry a byte area past 64 KiB, so no wrap is reachable
    /// today — but the next command added would inherit the pattern, and the
    /// frame length is the bound that cannot lie. Taking the smaller of the two
    /// means a wrapped count truncates rather than reading past the message.
    pub fn byte_area_len(&self) -> usize {
        let remaining = self.bytes.len().saturating_sub(self.byte_area_offset());
        usize::from(self.byte_count).min(remaining)
    }

    /// Where the byte area begins, measured from the start of the SMB message.
    pub fn byte_area_offset(&self) -> usize {
        HEADER_LEN + 1 + usize::from(self.word_count) * 2 + 2
    }

    /// The byte area, bounded by the message rather than by `ByteCount`.
    // Read by the per-command decoders, which arrive with the layers that issue
    // those commands.
    #[allow(dead_code)]
    pub fn byte_area(&self) -> &[u8] {
        &self.bytes[self.byte_area_offset()..]
    }

    /// Whether the frame carries a command body at all.
    ///
    /// `WordCount = 0` with an empty byte area is how SMB1 usually answers a
    /// failed command: the header's status is the whole of what it says.
    pub fn is_bodyless(&self) -> bool {
        self.word_count == 0
    }

    /// Refuses a message that is not this command carrying a `WordCount` this
    /// crate parses.
    ///
    /// A `WordCount` of zero is reported as [`WireError::NoResponseBody`]
    /// rather than as an unexpected count — but only where the command's
    /// response is supposed to carry words at all. `SMB_COM_CLOSE` and
    /// `SMB_COM_TREE_DISCONNECT` answer with no words when they succeed, so for
    /// those it is the ordinary shape and passes through here.
    fn expect_words(
        &self,
        command: u8,
        accepted: &[u8],
        describe: &'static str,
    ) -> Result<(), WireError> {
        if self.header.command != command {
            return Err(WireError::UnexpectedCommand {
                expected: command,
                actual: self.header.command,
            });
        }
        if accepted.contains(&self.word_count) {
            return Ok(());
        }
        if self.is_bodyless() {
            return Err(WireError::NoResponseBody {
                command,
                status: self.header.status,
            });
        }
        Err(WireError::UnexpectedWordCount {
            command,
            actual: self.word_count,
            expected: describe,
        })
    }

    /// Reads a block a server declared at an absolute offset.
    fn block(&self, field: &'static str, offset: usize, length: usize) -> Result<&[u8], WireError> {
        offsets::block_at(&self.bytes, field, offset, length)
    }
}

/// Assembles a complete SMB message from a header and a command body.
///
/// The body is the `WordCount` byte, the word block, the `ByteCount` and the
/// byte area — everything the encoders in this module produce.
pub fn message(header: &SmbHeader, body: &[u8]) -> Result<Vec<u8>, WireError> {
    use binrw::BinWrite;

    let mut out = Cursor::new(Vec::with_capacity(HEADER_LEN + body.len()));
    header.write(&mut out)?;
    let mut out = out.into_inner();
    out.extend_from_slice(body);
    Ok(out)
}

/// Wraps an SMB message in its NetBIOS session-message header.
pub fn frame(message: &[u8]) -> Result<Vec<u8>, WireError> {
    let header = netbios::encode_header(message.len())?;
    let mut out = Vec::with_capacity(netbios::HEADER_LEN + message.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(message);
    Ok(out)
}

/// Writes a `WordCount`, a word block, a `ByteCount` and a byte area.
///
/// `ByteCount` is written truncated to 16 bits deliberately: the field is 16
/// bits wide and the wire requires the truncation. Nothing reads it back as a
/// length.
fn body(words: &[u8], byte_area: &[u8]) -> Vec<u8> {
    debug_assert!(words.len().is_multiple_of(2));
    let mut out = Vec::with_capacity(1 + words.len() + 2 + byte_area.len());
    out.push((words.len() / 2) as u8);
    out.extend_from_slice(words);
    out.extend_from_slice(&(byte_area.len() as u16).to_le_bytes());
    out.extend_from_slice(byte_area);
    out
}

/// Encodes a string as the null-terminated UTF-16LE a Unicode-negotiated
/// connection carries.
fn utf16z(text: &str) -> Vec<u8> {
    let mut out: Vec<u8> = text.encode_utf16().flat_map(u16::to_le_bytes).collect();
    out.extend_from_slice(&[0, 0]);
    out
}

/// Decodes UTF-16LE, refusing what is not valid rather than decoding lossily.
fn from_utf16(field: &'static str, position: usize, bytes: &[u8]) -> Result<String, WireError> {
    let invalid = || WireError::InvalidUtf16 {
        field,
        position,
        bytes: bytes.to_vec(),
    };
    if !bytes.len().is_multiple_of(2) {
        return Err(invalid());
    }
    let units: Vec<u16> = bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| u16::from_le_bytes(pair))
        .collect();
    String::from_utf16(&units).map_err(|_| invalid())
}

/// Reads a `binrw` structure out of a word block.
fn read_words<T>(words: &[u8]) -> Result<T, WireError>
where
    T: for<'a> BinRead<Args<'a> = ()> + binrw::meta::ReadEndian,
{
    Ok(T::read(&mut Cursor::new(words))?)
}

/// Writes a `binrw` structure into a word block.
fn write_words<T>(value: &T) -> Result<Vec<u8>, WireError>
where
    T: for<'a> binrw::BinWrite<Args<'a> = ()> + binrw::meta::WriteEndian,
{
    let mut out = Cursor::new(Vec::new());
    value.write(&mut out)?;
    Ok(out.into_inner())
}
