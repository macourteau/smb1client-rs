//! `SMB_COM_TRANSACTION2` and `SMB_COM_TRANSACTION`.
//!
//! The two share a word layout exactly and differ in one thing: an
//! `SMB_COM_TRANSACTION` byte area opens with the transaction's name — the pipe
//! it addresses — and a TRANS2 byte area does not. So one encoder serves both,
//! which is also what keeps the two absolute-offset sites of this shape a
//! single piece of code.
//!
//! The padding between the header, the parameter block and the data block is
//! pinned by fixture bytes rather than reasoned about: this crate's design
//! campaign lost time to a 4-versus-2-byte parameter-block alignment mistake,
//! and getting it wrong moves every offset with it.

use binrw::binrw;

use super::header::command;
use super::{Message, WireError, body, offsets, read_words, write_words};

/// The `WordCount` of a transaction request, less its setup words.
const REQUEST_FIXED_WORDS: u8 = 14;

/// The `WordCount` of a transaction response, less its setup words.
const RESPONSE_FIXED_WORDS: u8 = 10;

/// The boundary the parameter and data blocks are placed on, measured from the
/// start of the SMB message.
///
/// Two, not four. Every committed TRANS2 request puts its byte area at message
/// offset 65 and declares `ParameterOffset = 66`: one pad byte. A four-byte
/// alignment would land the block on 68 and move every offset after it.
const BLOCK_ALIGNMENT: usize = 2;

/// The measured ceiling on `MaxParameterCount + MaxDataCount`.
///
/// Windows 11 24H2 rejects a transaction with `STATUS_INSUFF_SERVER_RESOURCES`
/// on the sum alone, at this threshold regardless of how the sum is split.
/// Samba applies no such limit. The number is measured; the sum being 65 KiB
/// less 36 bytes is a guess at the server's reasoning and nothing rests on it.
pub const MAX_RETURN_SUM: u32 = 66_524;

/// The floor every transaction asks for as `MaxParameterCount`.
///
/// A reply parameter block measures 10 bytes for `FIND_FIRST2` and 8 for
/// `FIND_NEXT2`, so the reference's 1024 spends budget on the wrong field.
/// Right-sizing it to the block each reply defines, never below this, leaves
/// room for a subcommand whose block was mis-sized and costs nothing worth
/// counting against the ceiling.
pub const MIN_MAX_PARAMETER_COUNT: u16 = 64;

/// The `MaxDataCount` this crate asks for, which with [`MIN_MAX_PARAMETER_COUNT`]
/// sums to 65,536 and leaves 988 bytes under the measured ceiling.
pub const MAX_DATA_COUNT: u16 = 65_472;

/// The fixed words of a transaction request.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RequestWords {
    total_parameter_count: u16,
    total_data_count: u16,
    max_parameter_count: u16,
    max_data_count: u16,
    max_setup_count: u8,
    reserved: u8,
    flags: u16,
    timeout: u32,
    reserved2: u16,
    parameter_count: u16,
    parameter_offset: u16,
    data_count: u16,
    data_offset: u16,
    setup_count: u8,
    reserved3: u8,
}

/// The fixed words of a transaction response.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResponseWords {
    total_parameter_count: u16,
    total_data_count: u16,
    reserved: u16,
    parameter_count: u16,
    parameter_offset: u16,
    parameter_displacement: u16,
    data_count: u16,
    data_offset: u16,
    data_displacement: u16,
    setup_count: u8,
    reserved2: u8,
}

/// The transaction name the RAP path addresses.
pub const PIPE_LANMAN: &str = "\\PIPE\\LANMAN";

/// The transaction name [MS-CIFS] requires on `TRANS_TRANSACT_NMPIPE`. The
/// pipe itself is named by the file id in the setup words.
pub const PIPE_TRANSACT_NAME: &str = "\\PIPE\\";

/// The `SMB_COM_TRANSACTION` subcommand that carries a DCE/RPC exchange on an
/// open pipe.
pub const TRANS_TRANSACT_NMPIPE: u16 = 0x0026;

/// How an `SMB_COM_TRANSACTION` spells its `Name`.
///
/// This is a fourth name-alignment site, and it is the one the reference
/// library gets wrong. Under `SMB_FLAGS2_UNICODE` the specification requires
/// the name to be UTF-16 and to begin on a two-byte boundary from the start of
/// the SMB header; the reference sets that flag and writes 8-bit ASCII at an
/// odd offset anyway, and Samba refuses the frame — reading the bytes as the
/// UTF-16 they claim to be and finding no pipe of that name.
///
/// The spelling is carried rather than chosen because both are in the corpus
/// and each has to re-encode to its own bytes. Nothing infers it from `Flags2`:
/// the reference sets that bit and writes ASCII regardless, which is the whole
/// defect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameEncoding {
    /// UTF-16LE, preceded by whatever padding lands it on a two-byte boundary.
    /// This is what the specification requires under `SMB_FLAGS2_UNICODE`, what
    /// a server accepts, and what this crate sends.
    Unicode,
    /// 8-bit ASCII, unaligned. The reference library's spelling, reproduced
    /// here only so that a captured frame re-encodes to its own bytes.
    Ascii,
}

/// The `Name` of an `SMB_COM_TRANSACTION`, and how it is spelled on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionName {
    /// The name itself, without its terminator.
    pub text: String,
    /// How it is written.
    pub encoding: NameEncoding,
}

impl TransactionName {
    /// A name spelled the way a conforming server requires.
    pub fn unicode(text: &str) -> Self {
        Self {
            text: text.to_owned(),
            encoding: NameEncoding::Unicode,
        }
    }
}

/// A TRANS2 or `SMB_COM_TRANSACTION` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionRequest {
    /// `SMB_COM_TRANSACTION2` or `SMB_COM_TRANSACTION`.
    ///
    /// It is carried rather than inferred from [`TransactionRequest::name`]:
    /// the named-pipe transact mode is an `SMB_COM_TRANSACTION` with no name at
    /// all, the pipe being identified by the file id in its setup words.
    pub command: u8,
    /// The most parameter bytes the reply may return.
    pub max_parameter_count: u16,
    /// The most data bytes the reply may return.
    pub max_data_count: u16,
    /// The most setup words the reply may return. Fixed at 0: none of the
    /// replies this crate asks for carries any.
    pub max_setup_count: u8,
    /// Fixed at 0. The two behaviours this field asks for — a one-way
    /// transaction, and disconnecting the tree afterwards — are neither wanted.
    pub flags: u16,
    /// Fixed at 0, which asks the server to block for as long as it needs. The
    /// client's own bound is its per-request timeout.
    pub timeout: u32,
    /// The setup words. TRANS2 carries one, its subcommand; the RAP and
    /// named-pipe paths carry the transaction's own.
    pub setup: Vec<u16>,
    /// The transaction name, on `SMB_COM_TRANSACTION` only, and how it is
    /// spelled.
    pub name: Option<TransactionName>,
    /// The parameter block.
    pub parameters: Vec<u8>,
    /// The data block.
    pub data: Vec<u8>,
}

impl TransactionRequest {
    /// A TRANS2 request carrying one subcommand setup word.
    pub fn trans2(subcommand: u16, parameters: Vec<u8>, data: Vec<u8>) -> Self {
        Self {
            command: command::TRANSACTION2,
            max_parameter_count: MIN_MAX_PARAMETER_COUNT,
            max_data_count: MAX_DATA_COUNT,
            max_setup_count: 0,
            flags: 0,
            timeout: 0,
            setup: vec![subcommand],
            name: None,
            parameters,
            data,
        }
    }

    /// A RAP request on `\\PIPE\\LANMAN`, whose byte area opens with that name.
    ///
    /// The name goes out as UTF-16LE on a two-byte boundary, which is what the
    /// specification requires of a client setting `SMB_FLAGS2_UNICODE` and what
    /// a server answers. It is **not** what the reference library sends: it
    /// writes 8-bit ASCII at an odd offset with that flag set, and Samba
    /// refuses the frame `STATUS_NOT_SUPPORTED`, having read the bytes as the
    /// UTF-16 they claim to be. `capture-trans/0009-c2s-cmd25.bin` is the
    /// refusal and `capture-rap/0009-c2s-cmd25.bin` is the same request spelled
    /// correctly and answered, two shares returned. The defect is reproduced by
    /// the codec so that the first of those re-encodes to its own bytes, and it
    /// is not inherited by anything this crate builds.
    ///
    /// **The setup block is empty**, which is a second departure from the
    /// reference and was found the same way. [MS-RAP] gives a RAP request no
    /// setup words; the reference hardcodes two zero words. Samba ignores them,
    /// dispatching on the name — but Windows rejects the frame as malformed and
    /// answers in DOS error format with `SMB_FLAGS2_NT_STATUS` cleared, which
    /// says nothing about RAP and reads like an answer to whatever question was
    /// being asked. `capture-win-rapsetup/` is that refusal.
    ///
    /// Their absence moves everything behind them: fourteen words rather than
    /// sixteen puts the byte area at 63, the name at 64 after its pad, and the
    /// parameters at 90. `capture-win-rap/0009-c2s-cmd25.bin` carries that
    /// shape, and is the fixture that pins what this crate sends;
    /// `capture-rap/` was taken before the setup words were understood and
    /// still carries the reference's two.
    pub fn rap(parameters: Vec<u8>, data: Vec<u8>) -> Self {
        Self {
            command: command::TRANSACTION,
            max_parameter_count: MIN_MAX_PARAMETER_COUNT,
            max_data_count: MAX_DATA_COUNT,
            max_setup_count: 0,
            flags: 0,
            timeout: 0,
            setup: Vec::new(),
            name: Some(TransactionName::unicode(PIPE_LANMAN)),
            parameters,
            data,
        }
    }

    /// A `TRANS_TRANSACT_NMPIPE` on an open pipe: one request written and one
    /// response returned, the pipe named by the file id in its setup words.
    ///
    /// **The `Name` is `\\PIPE\\`**, which is what [MS-CIFS] requires on this
    /// subcommand, spelled UTF-16LE like every other name this crate sends. The
    /// reference library sends the request with no name at all — the byte area
    /// of `capture-trans/0017-c2s-cmd25.bin` begins `05 00 0b 03`, the DCE/RPC
    /// bind PDU, with nothing in front of it — and that is recorded as
    /// known-wrong. It is invisible in practice only because the container
    /// refuses that client's transactions earlier, over the RAP name it
    /// mis-spells the same way.
    ///
    /// The reference asks for no parameter bytes back at all here. This crate
    /// asks for [`MIN_MAX_PARAMETER_COUNT`], which against the ceiling costs
    /// nothing worth counting and leaves room for a reply that carries some.
    pub fn pipe_transact(fid: u16, data: Vec<u8>) -> Self {
        Self {
            command: command::TRANSACTION,
            max_parameter_count: MIN_MAX_PARAMETER_COUNT,
            max_data_count: MAX_DATA_COUNT,
            max_setup_count: 0,
            flags: 0,
            timeout: 0,
            setup: vec![TRANS_TRANSACT_NMPIPE, fid],
            name: Some(TransactionName::unicode(PIPE_TRANSACT_NAME)),
            parameters: Vec::new(),
            data,
        }
    }

    /// Refuses a request the transaction rules forbid, before anything reaches
    /// the wire.
    ///
    /// Two limits, and they govern different things. The ceiling bounds what
    /// the request asks the server to *return*; a request's own parameter and
    /// data bytes are a separate question, and every transaction request must
    /// fit in one message within the negotiated `MaxBufferSize` — SMB1's
    /// secondary exchange is not implemented here, so a long path or a long
    /// search pattern is the realistic way that assumption breaks. Neither is
    /// truncated and neither is silently split.
    ///
    /// This belongs beside the one place that builds a transaction request. A
    /// size rule applied per call site is a rule the next call site added will
    /// not apply, and both failures are silent until a server complains.
    pub fn check_limits(&self, max_buffer_size: u32) -> Result<(), WireError> {
        let sum = u32::from(self.max_parameter_count) + u32::from(self.max_data_count);
        if sum > MAX_RETURN_SUM {
            return Err(WireError::FieldTooLong {
                field: "MaxParameterCount + MaxDataCount",
                length: sum as usize,
                limit: MAX_RETURN_SUM as usize,
            });
        }
        let encoded = self.encode_body()?.len() + super::header::HEADER_LEN;
        if encoded > max_buffer_size as usize {
            return Err(WireError::FieldTooLong {
                field: "transaction request",
                length: encoded,
                limit: max_buffer_size as usize,
            });
        }
        Ok(())
    }

    /// Encodes the command body, back-patching `ParameterOffset` and
    /// `DataOffset` from where the blocks actually land.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        let word_count = usize::from(REQUEST_FIXED_WORDS) + self.setup.len();

        let mut area = offsets::ByteArea::for_word_count(word_count);
        if let Some(name) = &self.name {
            match name.encoding {
                NameEncoding::Unicode => {
                    area.align_to(offsets::NAME_ALIGNMENT);
                    offsets::require_word_aligned("Name", area.offset())?;
                    area.put(&super::utf16z(&name.text));
                }
                NameEncoding::Ascii => {
                    area.put(name.text.as_bytes());
                    area.put(&[0]);
                }
            }
        }
        // An empty parameter block declares offset 0 and takes no space, and an
        // empty data block declares where it would have gone. The asymmetry is
        // the reference's and is pinned by fixture bytes on both sides: the RAP
        // request in `capture-trans/0009` has `ParameterOffset = 80` and a
        // `DataOffset` of 100 with no data, one pad byte past the end of its
        // parameters, while the named-pipe transact in `capture-trans/0017` has
        // `ParameterOffset = 0` and puts its data at 67, the first byte of the
        // byte area, unaligned.
        let parameter_offset = if self.parameters.is_empty() {
            0
        } else {
            let at = area.put_aligned(BLOCK_ALIGNMENT, &self.parameters);
            area.align_to(BLOCK_ALIGNMENT);
            at
        };
        let data_offset = area.put(&self.data);

        let words = RequestWords {
            total_parameter_count: self.parameters.len() as u16,
            total_data_count: self.data.len() as u16,
            max_parameter_count: self.max_parameter_count,
            max_data_count: self.max_data_count,
            max_setup_count: self.max_setup_count,
            reserved: 0,
            flags: self.flags,
            timeout: self.timeout,
            reserved2: 0,
            parameter_count: self.parameters.len() as u16,
            parameter_offset: parameter_offset as u16,
            data_count: self.data.len() as u16,
            data_offset: data_offset as u16,
            setup_count: self.setup.len() as u8,
            reserved3: 0,
        };

        let mut word_block = write_words(&words)?;
        for word in &self.setup {
            word_block.extend_from_slice(&word.to_le_bytes());
        }
        Ok(body(&word_block, &area.finish()))
    }

    /// Decodes a transaction request, so that a captured one can be re-encoded
    /// from its own fields.
    pub fn decode(message: &Message) -> Result<Self, WireError> {
        let command = message.header().command;
        if command != command::TRANSACTION2 && command != command::TRANSACTION {
            return Err(WireError::UnexpectedCommand {
                expected: command::TRANSACTION2,
                actual: command,
            });
        }
        if message.word_count() < REQUEST_FIXED_WORDS {
            return Err(WireError::UnexpectedWordCount {
                command,
                actual: message.word_count(),
                expected: "at least 14",
            });
        }
        let words: RequestWords = read_words(message.words())?;
        let setup = setup_words(message, REQUEST_FIXED_WORDS, words.setup_count)?;

        // The name, where there is one, fills the byte area up to whichever
        // block lands first. An offset of zero is a block that is not there.
        let name = if command == command::TRANSACTION {
            let first = [words.parameter_offset, words.data_offset]
                .into_iter()
                .filter(|&offset| offset != 0)
                .min()
                .map_or(0, usize::from);
            if first > message.byte_area_offset() {
                let area = message.byte_area_to_end();
                let end = first - message.byte_area_offset();
                let raw = area.get(..end).ok_or(WireError::Truncated {
                    part: "transaction Name",
                    declared: end,
                    length: area.len(),
                })?;
                Some(decode_name(message.byte_area_offset(), raw)?)
            } else {
                None
            }
        } else {
            None
        };

        Ok(Self {
            command,
            max_parameter_count: words.max_parameter_count,
            max_data_count: words.max_data_count,
            max_setup_count: words.max_setup_count,
            flags: words.flags,
            timeout: words.timeout,
            setup,
            name,
            parameters: message
                .block(
                    "ParameterOffset",
                    usize::from(words.parameter_offset),
                    usize::from(words.parameter_count),
                )?
                .to_vec(),
            data: message
                .block(
                    "DataOffset",
                    usize::from(words.data_offset),
                    usize::from(words.data_count),
                )?
                .to_vec(),
        })
    }
}

/// One message of a transaction reply.
///
/// A server may answer one request with several of these, each repeating the
/// request's multiplex id, each declaring the whole reply's totals and carrying
/// its own bytes at a displacement. Reassembling them belongs to the connection
/// task; this is the shape it reassembles.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TransactionResponse {
    /// The whole reply's parameter byte count, as this message declares it.
    pub total_parameter_count: u16,
    /// The whole reply's data byte count, as this message declares it.
    pub total_data_count: u16,
    /// Where this message's parameter bytes belong in the whole reply.
    pub parameter_displacement: u16,
    /// Where this message's data bytes belong in the whole reply.
    pub data_displacement: u16,
    /// The offset this message declared for its parameter block, kept so a
    /// reply can be re-encoded byte for byte. Servers do not agree on the
    /// padding, and nothing infers it.
    pub parameter_offset: u16,
    /// The offset this message declared for its data block.
    pub data_offset: u16,
    /// The setup words, of which the replies this crate asks for carry none.
    pub setup: Vec<u16>,
    /// This message's parameter bytes.
    pub parameters: Vec<u8>,
    /// This message's data bytes.
    pub data: Vec<u8>,
}

impl TransactionResponse {
    /// Decodes one message of a transaction reply, taking each block from the
    /// offset the server declared for it.
    pub fn decode(message: &Message) -> Result<Self, WireError> {
        let command = message.header().command;
        if command != command::TRANSACTION2 && command != command::TRANSACTION {
            return Err(WireError::UnexpectedCommand {
                expected: command::TRANSACTION2,
                actual: command,
            });
        }
        if message.word_count() < RESPONSE_FIXED_WORDS {
            return Err(if message.is_bodyless() {
                WireError::NoResponseBody {
                    command,
                    status: message.header().status,
                }
            } else {
                WireError::UnexpectedWordCount {
                    command,
                    actual: message.word_count(),
                    expected: "at least 10",
                }
            });
        }
        let words: ResponseWords = read_words(message.words())?;
        let setup = setup_words(message, RESPONSE_FIXED_WORDS, words.setup_count)?;

        Ok(Self {
            total_parameter_count: words.total_parameter_count,
            total_data_count: words.total_data_count,
            parameter_displacement: words.parameter_displacement,
            data_displacement: words.data_displacement,
            parameter_offset: words.parameter_offset,
            data_offset: words.data_offset,
            setup,
            parameters: message
                .block(
                    "ParameterOffset",
                    usize::from(words.parameter_offset),
                    usize::from(words.parameter_count),
                )?
                .to_vec(),
            data: message
                .block(
                    "DataOffset",
                    usize::from(words.data_offset),
                    usize::from(words.data_count),
                )?
                .to_vec(),
        })
    }

    /// Encodes the command body, placing each block at the offset the struct
    /// carries.
    ///
    /// The offsets are honoured rather than recomputed: Samba pads its data
    /// block to 4 bytes in one reply and not at all in another, so no single
    /// rule reproduces what a server sent.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        let word_count = usize::from(RESPONSE_FIXED_WORDS) + self.setup.len();
        let mut area = offsets::ByteArea::for_word_count(word_count);

        while area.offset() < usize::from(self.parameter_offset) {
            area.put(&[0]);
        }
        area.put(&self.parameters);
        while area.offset() < usize::from(self.data_offset) {
            area.put(&[0]);
        }
        area.put(&self.data);

        let words = ResponseWords {
            total_parameter_count: self.total_parameter_count,
            total_data_count: self.total_data_count,
            reserved: 0,
            parameter_count: self.parameters.len() as u16,
            parameter_offset: self.parameter_offset,
            parameter_displacement: self.parameter_displacement,
            data_count: self.data.len() as u16,
            data_offset: self.data_offset,
            data_displacement: self.data_displacement,
            setup_count: self.setup.len() as u8,
            reserved2: 0,
        };

        let mut word_block = write_words(&words)?;
        for word in &self.setup {
            word_block.extend_from_slice(&word.to_le_bytes());
        }
        Ok(body(&word_block, &area.finish()))
    }
}

/// Reads an `SMB_COM_TRANSACTION` `Name` and works out how it was spelled.
///
/// The spelling comes from the bytes and never from the header's `Flags2`: the
/// reference library sets `SMB_FLAGS2_UNICODE` and writes ASCII anyway, so the
/// flag says nothing about what follows. `region` is the byte area up to
/// whichever block lands first, which is exactly the space the name occupies.
///
/// A UTF-16 name is padded to a two-byte boundary, has an even number of bytes
/// after that pad, and ends in a null unit with no earlier one. An ASCII name
/// satisfies none of that except by coincidence — the reference's
/// `\PIPE\LANMAN` leaves 12 bytes after the pad ending `4e 00`, not `00 00`.
fn decode_name(byte_area_offset: usize, region: &[u8]) -> Result<TransactionName, WireError> {
    let pad = usize::from(!byte_area_offset.is_multiple_of(offsets::NAME_ALIGNMENT));
    if let Some(units) = region.get(pad..)
        && units.len() >= 2
        && units.len().is_multiple_of(2)
        && units.ends_with(&[0, 0])
        && !units[..units.len() - 2]
            .as_chunks::<2>()
            .0
            .iter()
            .any(|unit| unit == &[0, 0])
    {
        return Ok(TransactionName {
            text: super::from_utf16("Name", 0, &units[..units.len() - 2])?,
            encoding: NameEncoding::Unicode,
        });
    }

    let end = region
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(region.len());
    // The one lossy decode in this crate, and it is bounded to a place where
    // nothing acts on the result. A *filename* that is not valid UTF-16 fails
    // its listing rather than coming back mangled, because a caller would go on
    // to use it as a path. This is a transaction name on the decode side only:
    // the port never builds an ASCII one, so the only bytes that reach here are
    // a captured frame's, and what the text is used for is a fixture assertion
    // and a log line.
    Ok(TransactionName {
        text: String::from_utf8_lossy(&region[..end]).into_owned(),
        encoding: NameEncoding::Ascii,
    })
}

/// Reads the setup words that follow a transaction's fixed word block.
fn setup_words(message: &Message, fixed: u8, declared: u8) -> Result<Vec<u16>, WireError> {
    let start = usize::from(fixed) * 2;
    let end = start + usize::from(declared) * 2;
    let words = message.words();
    let raw = words.get(start..end).ok_or(WireError::Truncated {
        part: "setup words",
        declared: end,
        length: words.len(),
    })?;
    Ok(raw
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&pair| u16::from_le_bytes(pair))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ceiling_is_on_the_sum_and_not_on_either_field() {
        let mut request = TransactionRequest::trans2(0x0001, vec![0; 18], Vec::new());
        request.max_parameter_count = 1024;
        request.max_data_count = 65_500;
        assert!(request.check_limits(65_535).is_ok());

        request.max_data_count = 65_501;
        assert!(matches!(
            request.check_limits(65_535),
            Err(WireError::FieldTooLong { length: 66_525, .. })
        ));

        request.max_parameter_count = 16_384;
        request.max_data_count = 50_140;
        assert!(request.check_limits(65_535).is_ok());
        request.max_data_count = 50_141;
        assert!(matches!(
            request.check_limits(65_535),
            Err(WireError::FieldTooLong { length: 66_525, .. })
        ));
    }

    #[test]
    fn a_request_that_does_not_itself_fit_fails_locally() {
        let request = TransactionRequest::trans2(0x0005, vec![0; 5000], Vec::new());
        assert!(request.check_limits(65_535).is_ok());
        assert!(matches!(
            request.check_limits(4356),
            Err(WireError::FieldTooLong {
                field: "transaction request",
                ..
            })
        ));
    }

    /// The RAP shape this crate sends, pinned against
    /// `capture-win-rap/0009-c2s-cmd25.bin` — a request Windows parsed rather
    /// than refused, which is what makes it the oracle here.
    ///
    /// **Not** `capture-rap/0009-c2s-cmd25.bin`, which is the same request from
    /// a harness corrected only for the name: it still carries the reference's
    /// two zero setup words, and those move every offset behind them. That
    /// corpus stays in the sweep, and re-encodes to its own bytes, because the
    /// codec reproduces what a frame contains; it is simply not what this crate
    /// builds.
    #[test]
    fn a_named_transaction_places_its_blocks_after_the_name() {
        let request = TransactionRequest::rap(
            b"\x00\x00WrLeh\0B13BWz\0\x01\x00\xff\xff".to_vec(),
            Vec::new(),
        );
        assert_eq!(request.command, command::TRANSACTION);
        let encoded = request.encode_body().unwrap();
        let words: RequestWords = read_words(&encoded[1..1 + 28]).unwrap();
        // No setup words, so fourteen words rather than sixteen put the byte
        // area on 63. One pad byte lands the name on 64, 26 bytes of UTF-16
        // with its terminator end on 90, and the 19-byte parameter block ends
        // odd, so one more pad puts `DataOffset` on 110 with no data there.
        assert_eq!(words.setup_count, 0);
        assert_eq!(words.parameter_offset, 90);
        assert_eq!(words.parameter_count, 19);
        assert_eq!(words.data_offset, 110);
        assert_eq!(words.data_count, 0);
        assert_eq!(
            encoded[1 + 28..1 + 28 + 2],
            (1u16 + 26 + 19 + 1).to_le_bytes()
        );

        // The arithmetic above is the crate's; these are the bytes a live
        // Windows server accepted. A test that only checked the former would
        // agree with itself.
        let (_, captured) = crate::wire::fixtures::frame("capture-win-rap/0009-c2s-cmd25.bin");
        let their_words: RequestWords = read_words(&captured[33..33 + 28]).unwrap();
        assert_eq!(words.setup_count, their_words.setup_count);
        assert_eq!(words.parameter_offset, their_words.parameter_offset);
        assert_eq!(words.data_offset, their_words.data_offset);
    }

    /// The named-pipe transact shape, pinned against
    /// `capture-win-nmpipe/0011-c2s-cmd25.bin`: `\PIPE\` in UTF-16 after one
    /// pad byte, `ParameterOffset = 0`, and the payload at 82.
    ///
    /// **Not** `capture-trans/0017-c2s-cmd25.bin`, which is the reference
    /// library's own frame and carries no name at all — the defect recorded
    /// under Where the Go library is the oracle, and where it is not. That
    /// corpus still re-encodes to its own bytes, because the codec reproduces
    /// what a frame contains; it is simply not what this crate builds.
    #[test]
    fn a_pipe_transact_names_the_pipe_and_declares_no_parameter_offset() {
        let request = TransactionRequest::pipe_transact(0x4003, vec![0xAA; 116]);
        let encoded = request.encode_body().unwrap();
        let words: RequestWords = read_words(&encoded[1..1 + 28]).unwrap();
        // Two setup words put the byte area on 67, which is odd, so one pad
        // byte lands the name on 68; fourteen bytes of UTF-16 with its
        // terminator end on 82, where the payload starts unaligned.
        assert_eq!(words.setup_count, 2);
        assert_eq!(words.parameter_offset, 0);
        assert_eq!(words.parameter_count, 0);
        assert_eq!(words.data_offset, 82);
        assert_eq!(words.data_count, 116);
        assert_eq!(encoded[1 + 32..1 + 32 + 2], (1u16 + 14 + 116).to_le_bytes());

        // The arithmetic above is the crate's; these are the bytes a live
        // Windows server answered `STATUS_SUCCESS`.
        let (_, captured) = crate::wire::fixtures::frame("capture-win-nmpipe/0011-c2s-cmd25.bin");
        let their_words: RequestWords = read_words(&captured[33..33 + 32]).unwrap();
        assert_eq!(words.setup_count, their_words.setup_count);
        assert_eq!(words.parameter_offset, their_words.parameter_offset);
        assert_eq!(words.data_offset, their_words.data_offset);
        assert_eq!(
            TransactionRequest::decode(&Message::parse(captured).unwrap())
                .unwrap()
                .name,
            request.name
        );
    }
}
