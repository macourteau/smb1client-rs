//! `SMB_COM_NEGOTIATE`.
//!
//! One dialect is offered, `NT LM 0.12`, and the response is parsed by
//! `WordCount` rather than by the dialect.
//!
//! The reference library offers three — `NT LM 0.12`, `NT LANMAN 1.0`,
//! `LANMAN1.0` — and the extra two create a disagreement: against that
//! three-entry list Windows 11 24H2 answers `DialectIndex = 0` while both
//! Samba-family servers answer `1`, which is literally `NT LANMAN 1.0`, and yet
//! all three return the same 17-word NT LM 0.12 response body. A client that
//! validated the selection by index, or mapped the index back to a dialect
//! name, would pass against one server family and fail against the other.
//! Offering one dialect removes the question.

use binrw::binrw;

use super::header::{HEADER_LEN, command};
use super::{Message, WireError, body, offsets, read_words, write_words};

/// The one dialect this crate offers.
pub const NT_LM_0_12: &str = "NT LM 0.12";

/// The `DialectIndex` a server returns when it accepted nothing on offer.
pub const NO_COMMON_DIALECT: u16 = 0xFFFF;

/// The byte that introduces each entry of the dialect list.
const DIALECT_ENTRY: u8 = 0x02;

/// The `WordCount` of the NT LM 0.12 negotiate response.
const RESPONSE_WORDS: u8 = 17;

/// A negotiate request: the dialects offered, in the order they are offered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateRequest {
    /// The dialect strings, without their `0x02` markers or terminators.
    pub dialects: Vec<String>,
}

impl NegotiateRequest {
    /// The offer this crate makes.
    pub fn single_dialect() -> Self {
        Self {
            dialects: vec![NT_LM_0_12.to_owned()],
        }
    }

    /// Encodes the command body.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        let mut area = offsets::ByteArea::for_word_count(0);
        for dialect in &self.dialects {
            area.put(&[DIALECT_ENTRY]);
            area.put(dialect.as_bytes());
            area.put(&[0]);
        }
        Ok(body(&[], &area.finish()))
    }

    /// Decodes a negotiate request. Requests are decoded so that a captured one
    /// can be re-encoded from its own fields.
    pub fn decode(message: &Message) -> Result<Self, WireError> {
        if message.header().command != command::NEGOTIATE {
            return Err(WireError::UnexpectedCommand {
                expected: command::NEGOTIATE,
                actual: message.header().command,
            });
        }
        let area = message.block(
            "ByteCount",
            message.byte_area_offset(),
            usize::from(message.byte_count()),
        )?;
        let mut dialects = Vec::new();
        let mut rest = area;
        while let Some((&marker, tail)) = rest.split_first() {
            if marker != DIALECT_ENTRY {
                return Err(WireError::Truncated {
                    part: "dialect list",
                    declared: area.len(),
                    length: area.len() - rest.len(),
                });
            }
            let end = tail
                .iter()
                .position(|&byte| byte == 0)
                .ok_or(WireError::Truncated {
                    part: "dialect string",
                    declared: area.len(),
                    length: area.len() - rest.len(),
                })?;
            dialects.push(String::from_utf8_lossy(&tail[..end]).into_owned());
            rest = &tail[end + 1..];
        }
        Ok(Self { dialects })
    }
}

/// The 17 words of an NT LM 0.12 negotiate response.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NegotiateWords {
    /// The index into the offered list the server selected.
    pub dialect_index: u16,
    /// User-level or share-level security, and whether signing is offered.
    pub security_mode: u8,
    /// The most requests the server will work on at once.
    pub max_mpx_count: u16,
    /// The most virtual circuits the server permits.
    pub max_number_vcs: u16,
    /// The largest single SMB message the server will accept.
    ///
    /// This is not a ceiling on a transaction's `MaxDataCount`, and it bounds
    /// `READ_ANDX`/`WRITE_ANDX` chunks only where the large-I/O capabilities
    /// are absent. It is 32 bits here, unlike the `USHORT` field of the same
    /// name in `SESSION_SETUP_ANDX`.
    pub max_buffer_size: u32,
    /// The largest raw-mode transfer, which this crate does not use.
    pub max_raw_size: u32,
    /// An opaque session identifier.
    pub session_key: u32,
    /// The server's capability word.
    pub capabilities: u32,
    /// The server's clock, in Windows FILETIME units.
    pub system_time: i64,
    /// Minutes west of UTC.
    pub server_time_zone: i16,
    /// Zero under extended security, where the byte area carries a SPNEGO blob
    /// instead of a challenge.
    pub encryption_key_length: u8,
}

/// A negotiate response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NegotiateResponse {
    /// The fixed words.
    pub words: NegotiateWords,
    /// The server's GUID, the first 16 bytes of the byte area.
    pub server_guid: [u8; 16],
    /// The SPNEGO `NegTokenInit2` the server offers. Nothing in the exchange
    /// depends on it and this crate does not parse it.
    pub security_blob: Vec<u8>,
}

impl NegotiateResponse {
    /// Decodes a negotiate response.
    ///
    /// The shape is keyed off `WordCount` alone: 17 words is the NT LM 0.12
    /// response this crate parses, and any other count is refused as a dialect
    /// it does not implement.
    pub fn decode(message: &Message) -> Result<Self, WireError> {
        message.expect_words(command::NEGOTIATE, &[RESPONSE_WORDS], "17")?;
        let words: NegotiateWords = read_words(message.words())?;

        let area = message.block(
            "ByteCount",
            message.byte_area_offset(),
            usize::from(message.byte_count()),
        )?;
        let (guid, blob) = area.split_at_checked(16).ok_or(WireError::Truncated {
            part: "ServerGUID",
            declared: 16,
            length: area.len(),
        })?;

        Ok(Self {
            words,
            server_guid: guid.try_into().expect("split at 16"),
            security_blob: blob.to_vec(),
        })
    }

    /// Refuses a selection this crate did not offer.
    ///
    /// Against a single-dialect offer the only index a conforming server may
    /// return is 0. [`NO_COMMON_DIALECT`] is the one diagnosable failure — the
    /// server saying it accepted nothing on offer — and any other index is
    /// refused the same way, since a server may only choose from the list it
    /// was given.
    ///
    /// This is separate from decoding on purpose. The committed captures were
    /// taken by a client offering three dialects, so they carry indices this
    /// check refuses while their bytes still pin the codec.
    pub fn accepted_offered_dialect(&self) -> Result<(), WireError> {
        match self.words.dialect_index {
            0 => Ok(()),
            NO_COMMON_DIALECT => Err(WireError::NoCommonDialect),
            other => Err(WireError::UnsupportedDialectIndex(other)),
        }
    }

    /// Encodes the command body, which is what a captured response is
    /// re-encoded through.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        let mut area = offsets::ByteArea::at(HEADER_LEN + 1 + 34 + 2);
        area.put(&self.server_guid);
        area.put(&self.security_blob);
        Ok(body(&write_words(&self.words)?, &area.finish()))
    }
}
