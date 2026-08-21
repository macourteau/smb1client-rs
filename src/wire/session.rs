//! Session-scoped commands: `SMB_COM_SESSION_SETUP_ANDX` and
//! `SMB_COM_LOGOFF_ANDX`.

use binrw::binrw;

use super::andx::AndX;
use super::header::command;
use super::{Message, WireError, body, offsets, read_words, utf16z, write_words};

/// The `WordCount` of a logoff in either direction.
const LOGOFF_WORDS: u8 = 2;

/// The `WordCount` of an extended-security session setup request.
const SETUP_REQUEST_WORDS: u8 = 12;

/// The `WordCount` of an extended-security session setup response.
const SETUP_RESPONSE_WORDS: u8 = 4;

/// The `Action` bit that says the server logged the client on as a guest.
pub const ACTION_GUEST: u16 = 0x0001;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LogoffWords {
    andx: AndX,
}

/// `SMB_COM_LOGOFF_ANDX`. It carries the AndX prologue and nothing else.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogoffAndx {
    /// The AndX prologue as it arrived. Nothing consults its offset; it is kept
    /// because it is what the frame said.
    pub andx: AndX,
}

impl LogoffAndx {
    /// A logoff request, chaining nothing.
    pub fn request() -> Self {
        Self { andx: AndX::NONE }
    }

    /// Encodes the command body.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        Ok(body(&write_words(&LogoffWords { andx: self.andx })?, &[]))
    }

    /// Decodes a logoff in either direction.
    ///
    /// Two committed Windows logoff responses carry `AndXOffset = 39`, which is
    /// the SMB message length exactly, beside `AndXCommand = 0xFF`. The
    /// sentinel is what says there is no next command; the offset is read and
    /// ignored.
    pub fn decode(message: &Message) -> Result<Self, WireError> {
        message.expect_words(command::LOGOFF_ANDX, &[LOGOFF_WORDS], "2")?;
        let words: LogoffWords = read_words(message.words())?;
        words.andx.refuse_chaining()?;
        Ok(Self { andx: words.andx })
    }
}

/// The 12 words of an extended-security `SESSION_SETUP_ANDX` request.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SetupRequestWords {
    andx: AndX,
    /// The largest SMB message the *client* will accept.
    ///
    /// It is a `USHORT` here, unlike the negotiate response's 32-bit field of
    /// the same name, so 65,535 is the largest value it can carry and is what
    /// this crate advertises. That number is also the threshold at which a
    /// reply arrives in several messages at all, since a server splits a larger
    /// reply to fit it.
    max_buffer_size: u16,
    max_mpx_count: u16,
    vc_number: u16,
    /// The negotiate response's `SessionKey`, echoed back as [MS-CIFS] asks.
    session_key: u32,
    security_blob_length: u16,
    reserved: u32,
    /// The capabilities the *client* implements, not the server's word echoed
    /// back.
    capabilities: u32,
}

/// The 4 words of an extended-security `SESSION_SETUP_ANDX` response.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SetupResponseWords {
    andx: AndX,
    action: u16,
    security_blob_length: u16,
}

/// A `SESSION_SETUP_ANDX` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSetupAndx {
    /// The largest SMB message this client will accept.
    pub max_buffer_size: u16,
    /// What this client will keep outstanding, which is the admission limit it
    /// then enforces.
    pub max_mpx_count: u16,
    /// The negotiate response's `SessionKey`.
    pub session_key: u32,
    /// The capability word this client implements.
    pub capabilities: u32,
    /// The SPNEGO token.
    pub security_blob: Vec<u8>,
    /// What the client calls itself. It identifies the crate rather than a host
    /// operating system: a wire-visible identity string is worth reporting
    /// honestly or not at all.
    pub native_os: String,
    /// The second half of the same identity.
    pub native_lan_man: String,
}

impl SessionSetupAndx {
    /// Encodes the command body.
    ///
    /// **The pad before `NativeOS` is computed, not written as a constant.**
    /// The byte area begins at 59 — odd — and the strings sit *after* a
    /// security blob whose length varies with the SPNEGO token, so the parity
    /// they land on moves with it. Getting this wrong shifts every character of
    /// both strings by a byte, which a server honouring the alignment reads as
    /// mojibake rather than as an error.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        let words = SetupRequestWords {
            andx: AndX::NONE,
            max_buffer_size: self.max_buffer_size,
            max_mpx_count: self.max_mpx_count,
            vc_number: 0,
            session_key: self.session_key,
            security_blob_length: u16::try_from(self.security_blob.len()).map_err(|_| {
                WireError::FieldTooLong {
                    field: "SecurityBlobLength",
                    length: self.security_blob.len(),
                    limit: usize::from(u16::MAX),
                }
            })?,
            reserved: 0,
            capabilities: self.capabilities,
        };

        let mut area = offsets::ByteArea::for_word_count(usize::from(SETUP_REQUEST_WORDS));
        area.put(&self.security_blob);
        area.align_to(offsets::NAME_ALIGNMENT);
        let native_os_at = area.put(&utf16z(&self.native_os));
        offsets::require_word_aligned("NativeOS", native_os_at)?;
        area.put(&utf16z(&self.native_lan_man));

        Ok(body(&write_words(&words)?, &area.finish()))
    }
}

/// A `SESSION_SETUP_ANDX` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionSetupResponse {
    /// The `Action` word. Bit 0 says the server logged the client on as a
    /// guest, which on many servers is what a wrong password produces.
    pub action: u16,
    /// The SPNEGO token, empty on a server that issued no challenge.
    pub security_blob: Vec<u8>,
    /// What the server calls itself, where the strings decoded. They are
    /// diagnostics and nothing branches on them, so a server that writes them
    /// unaligned or truncated costs a log line rather than a connection.
    pub server_strings: Vec<String>,
}

impl SessionSetupResponse {
    /// Decodes a session setup response.
    ///
    /// The frame carrying `STATUS_MORE_PROCESSING_REQUIRED` is decoded here
    /// like any other: it sits inside the error class but carries four words
    /// and a byte area, because that frame *is* the NTLM challenge. Nothing in
    /// this layer branches on the status.
    pub fn decode(message: &Message) -> Result<Self, WireError> {
        message.expect_words(command::SESSION_SETUP_ANDX, &[SETUP_RESPONSE_WORDS], "4")?;
        let words: SetupResponseWords = read_words(message.words())?;
        words.andx.refuse_chaining()?;

        let blob_length = usize::from(words.security_blob_length);
        let blob_at = message.byte_area_offset();
        let security_blob = message
            .block("SecurityBlobLength", blob_at, blob_length)?
            .to_vec();

        // The strings sit behind the blob, on the same 2-byte boundary the
        // request's do. They are informational, so an unreadable tail is
        // reported as no strings rather than as a failed handshake.
        let mut at = blob_at + blob_length;
        if !at.is_multiple_of(offsets::NAME_ALIGNMENT) {
            at += 1;
        }
        let server_strings = message
            .as_bytes()
            .get(at..)
            .map(decode_string_run)
            .unwrap_or_default();

        Ok(Self {
            action: words.action,
            security_blob,
            server_strings,
        })
    }

    /// Whether the server logged the client on as a guest.
    pub fn is_guest(&self) -> bool {
        self.action & ACTION_GUEST != 0
    }
}

/// Splits a run of null-terminated UTF-16LE strings, stopping at the first one
/// that does not decode.
fn decode_string_run(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = Vec::new();
    for &pair in bytes.as_chunks::<2>().0 {
        let unit = u16::from_le_bytes(pair);
        if unit == 0 {
            match String::from_utf16(&current) {
                Ok(text) => out.push(text),
                Err(_) => return out,
            }
            current.clear();
        } else {
            current.push(unit);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::header::HEADER_LEN;

    /// The byte area begins at 59, which is odd, so a blob of even length puts
    /// the strings on an odd offset and the pad is what moves them back. An
    /// odd-length blob needs none — which is the case a constant pad gets
    /// wrong.
    #[test]
    fn the_pad_before_native_os_follows_the_blob_length() {
        for blob_length in [0usize, 1, 40, 74, 345, 382] {
            let setup = SessionSetupAndx {
                max_buffer_size: 65_535,
                max_mpx_count: 50,
                session_key: 0,
                capabilities: 0,
                security_blob: vec![0xAB; blob_length],
                native_os: "smb1client-rs".to_owned(),
                native_lan_man: "smb1client-rs".to_owned(),
            };
            let body = setup.encode_body().unwrap();
            let area_at = HEADER_LEN + 1 + 24 + 2;
            assert_eq!(area_at, 59);
            let area = &body[1 + 24 + 2..];
            let unpadded = area_at + blob_length;
            let strings_at = unpadded + usize::from(!unpadded.is_multiple_of(2));
            assert!(
                strings_at.is_multiple_of(2),
                "NativeOS must be word-aligned"
            );
            // "s" is the first character of the crate's name in UTF-16LE.
            assert_eq!(area[strings_at - area_at], b's');
        }
    }

    #[test]
    fn the_guest_bit_is_bit_zero_of_action() {
        let guest = SessionSetupResponse {
            action: 0x0001,
            security_blob: Vec::new(),
            server_strings: Vec::new(),
        };
        assert!(guest.is_guest());
        let named = SessionSetupResponse {
            action: 0x0000,
            ..guest.clone()
        };
        assert!(!named.is_guest());
        // Bit 1 is `SMB_SETUP_USE_LANMAN_KEY` and says nothing about guests.
        let other = SessionSetupResponse {
            action: 0x0002,
            ..guest
        };
        assert!(!other.is_guest());
    }
}
