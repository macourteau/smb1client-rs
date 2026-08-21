//! NTLMv2, written from [MS-NLMP].
//!
//! Three messages make the exchange: the client's NEGOTIATE, the server's
//! CHALLENGE, and the client's AUTHENTICATE. Only NTLMv2 is implemented — the
//! `LmChallengeResponse` this crate sends is 24 zero bytes, which is what
//! [MS-NLMP] 3.1.5.1.2 asks of a client whose challenge travels in the response
//! itself.
//!
//! # The nine flags
//!
//! The NEGOTIATE message carries [`NEGOTIATE_FLAGS`] and no others, and every
//! bit in it is taken from [MS-NLMP] 2.2.2.5. Two the reference library sends
//! are deliberately absent and the reasons differ in emphasis but not in kind.
//!
//! `NTLMSSP_NEGOTIATE_ALWAYS_SIGN` advertises a signing capability this crate
//! never exercises. `NTLMSSP_NEGOTIATE_VERSION` carries a structure claiming a
//! Windows major, minor and build, and this crate is not Windows. Both are
//! false claims and both are dropped.
//!
//! **`NTLMSSP_NEGOTIATE_SIGN` stays, and removing it breaks Windows
//! outright.** Measured against Windows 11 24H2: with `SIGN` present
//! authentication succeeds whether or not `ALWAYS_SIGN` is there, and with
//! `SIGN` absent Windows answers `STATUS_INVALID_PARAMETER` and authentication
//! never happens at all. The likely mechanism is the key exchange —
//! `NTLMSSP_NEGOTIATE_KEY_EXCH` is set, and the encrypted session key it
//! carries is only meaningful when signing or sealing is negotiated — but
//! whatever the cause, the flag stays and the reason is recorded here so it is
//! not cleaned up later.

use digest::{Digest, KeyInit, Mac};
use hmac::Hmac;
use md4::Md4;
use md5::Md5;
use rc4::Rc4;
use rc4::cipher::StreamCipher;

use std::fmt;

use super::Credentials;

/// `NTLMSSP_NEGOTIATE_UNICODE`.
pub const NEGOTIATE_UNICODE: u32 = 0x0000_0001;
/// `NTLMSSP_REQUEST_TARGET`.
pub const REQUEST_TARGET: u32 = 0x0000_0004;
/// `NTLMSSP_NEGOTIATE_SIGN`. Load-bearing: see the module documentation.
pub const NEGOTIATE_SIGN: u32 = 0x0000_0010;
/// `NTLMSSP_NEGOTIATE_NTLM`.
pub const NEGOTIATE_NTLM: u32 = 0x0000_0200;
/// `NTLMSSP_NEGOTIATE_ALWAYS_SIGN`. Deliberately **not** sent.
pub const NEGOTIATE_ALWAYS_SIGN: u32 = 0x0000_8000;
/// `NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY`.
pub const NEGOTIATE_EXTENDED_SESSIONSECURITY: u32 = 0x0008_0000;
/// `NTLMSSP_NEGOTIATE_TARGET_INFO`.
pub const NEGOTIATE_TARGET_INFO: u32 = 0x0080_0000;
/// `NTLMSSP_NEGOTIATE_VERSION`. Deliberately **not** sent.
pub const NEGOTIATE_VERSION: u32 = 0x0200_0000;
/// `NTLMSSP_NEGOTIATE_128`.
pub const NEGOTIATE_128: u32 = 0x2000_0000;
/// `NTLMSSP_NEGOTIATE_KEY_EXCH`.
pub const NEGOTIATE_KEY_EXCH: u32 = 0x4000_0000;
/// `NTLMSSP_NEGOTIATE_56`.
pub const NEGOTIATE_56: u32 = 0x8000_0000;

/// The nine flags the NEGOTIATE message carries, and no others.
pub const NEGOTIATE_FLAGS: u32 = NEGOTIATE_UNICODE
    | REQUEST_TARGET
    | NEGOTIATE_SIGN
    | NEGOTIATE_NTLM
    | NEGOTIATE_EXTENDED_SESSIONSECURITY
    | NEGOTIATE_TARGET_INFO
    | NEGOTIATE_128
    | NEGOTIATE_KEY_EXCH
    | NEGOTIATE_56;

/// The eight bytes every NTLM message opens with.
const SIGNATURE: &[u8; 8] = b"NTLMSSP\0";

const MESSAGE_NEGOTIATE: u32 = 1;
const MESSAGE_CHALLENGE: u32 = 2;
const MESSAGE_AUTHENTICATE: u32 = 3;

/// The NEGOTIATE message's fixed length: the header, two empty field
/// descriptors and the eight `Version` bytes [MS-NLMP] 2.2.1.1 keeps in place
/// whether or not `NTLMSSP_NEGOTIATE_VERSION` is set.
const NEGOTIATE_LEN: usize = 40;

/// Where an AUTHENTICATE message's payload begins when it carries no MIC: the
/// fixed fields and the `Version` field.
const AUTHENTICATE_HEADER_LEN: usize = 72;
/// Where the MIC sits, and how much longer the header is when one is present.
const MIC_OFFSET: usize = 72;
/// The length of the MIC, and of every other digest here.
const DIGEST_LEN: usize = 16;

/// The smallest CHALLENGE this crate will read: through `TargetInfoFields`.
/// The `Version` field beyond it is optional and is not read.
const CHALLENGE_MIN_LEN: usize = 48;

/// `MsvAvEOL`, which ends an AV pair list.
const AV_EOL: u16 = 0x0000;
/// `MsvAvFlags`.
const AV_FLAGS: u16 = 0x0006;
/// `MsvAvTimestamp`.
const AV_TIMESTAMP: u16 = 0x0007;
/// The `MsvAvFlags` bit that says the AUTHENTICATE message carries a MIC.
const AV_FLAG_MIC_PROVIDED: u32 = 0x0000_0002;

/// The 100-nanosecond ticks between 1601-01-01 and the Unix epoch.
const FILETIME_EPOCH_OFFSET: i128 = 116_444_736_000_000_000;

/// What can go wrong reading a server's NTLM message.
///
/// Every variant here is reachable by an unauthenticated peer: the CHALLENGE
/// arrives before authentication has completed, and its AV pairs are
/// server-supplied. The parser is fuzzed for that reason.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum NtlmError {
    /// The message did not begin with `NTLMSSP\0`.
    #[error("NTLM message does not carry the NTLMSSP signature")]
    NotNtlm,

    /// The message type was not the one expected at this point in the exchange.
    #[error("expected NTLM message type {expected}, found {actual}")]
    UnexpectedMessageType {
        /// What the exchange was waiting for.
        expected: u32,
        /// What arrived.
        actual: u32,
    },

    /// The message ended inside a field.
    #[error("NTLM message of {length} bytes is shorter than its {part} needs")]
    Truncated {
        /// The part that ran out.
        part: &'static str,
        /// The bytes the message holds.
        length: usize,
    },

    /// A field descriptor's offset and length point outside the message.
    #[error(
        "NTLM {field} at offset {offset} for {length} bytes falls outside a {message_length}-byte message"
    )]
    FieldOutOfRange {
        /// The field that declared it.
        field: &'static str,
        /// The offset declared.
        offset: usize,
        /// The length declared.
        length: usize,
        /// The message the offset was read against.
        message_length: usize,
    },

    /// An AV pair ran past the end of the target info, or the list never ended.
    #[error("the CHALLENGE message's AV pair list is malformed at byte {0}")]
    MalformedAvPairs(usize),

    /// The server offered no extended session security, which this crate
    /// requires: without it there is no NTLMv2 exchange to have.
    #[error("the server's CHALLENGE does not negotiate extended session security")]
    NoExtendedSessionSecurity,
}

/// The NT hash: `MD4(UTF16LE(password))`.
///
/// It is pass-the-hash-equivalent — anyone holding it can authenticate as the
/// user without ever knowing the password — so it carries the same redacted
/// [`Debug`] the password does, and for the same reason.
#[derive(Clone, PartialEq, Eq)]
struct NtHash([u8; DIGEST_LEN]);

impl NtHash {
    fn of(password: &str) -> Self {
        let utf16: Vec<u8> = password.encode_utf16().flat_map(u16::to_le_bytes).collect();
        let mut hash = [0u8; DIGEST_LEN];
        hash.copy_from_slice(&Md4::digest(&utf16));
        Self(hash)
    }
}

impl fmt::Debug for NtHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NtHash(<redacted>)")
    }
}

/// `HMAC_MD5`, which is the whole of NTLMv2's key schedule.
fn hmac_md5(key: &[u8], message: &[u8]) -> [u8; DIGEST_LEN] {
    let mut mac = <Hmac<Md5> as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    mac.update(message);
    let mut out = [0u8; DIGEST_LEN];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// `NTOWFv2(Passwd, User, UserDom)` — [MS-NLMP] 3.3.2.
///
/// The user name is upper-cased and the domain is not, which is a property of
/// the specification rather than an oversight: the two are concatenated and
/// only the first half is folded.
fn ntowf_v2(credentials: &Credentials) -> [u8; DIGEST_LEN] {
    let hash = NtHash::of(credentials.password.expose());
    let identity: Vec<u8> = credentials
        .user()
        .to_uppercase()
        .encode_utf16()
        .chain(credentials.domain().encode_utf16())
        .flat_map(u16::to_le_bytes)
        .collect();
    hmac_md5(&hash.0, &identity)
}

/// The NEGOTIATE message the client opens with.
///
/// It carries no domain and no workstation. The `Version` field is present and
/// zero, which is what [MS-NLMP] 2.2.1.1 asks of a message that does not set
/// `NTLMSSP_NEGOTIATE_VERSION`.
pub fn negotiate_message() -> [u8; NEGOTIATE_LEN] {
    let mut message = [0u8; NEGOTIATE_LEN];
    message[0..8].copy_from_slice(SIGNATURE);
    message[8..12].copy_from_slice(&MESSAGE_NEGOTIATE.to_le_bytes());
    message[12..16].copy_from_slice(&NEGOTIATE_FLAGS.to_le_bytes());
    // `DomainNameFields` at 16, `WorkstationFields` at 24 and `Version` at 32
    // are all zero, which is what an empty field descriptor and an unclaimed
    // version look like.
    message
}

/// A field descriptor: a length, a maximum length and an absolute offset.
fn field(message: &[u8], at: usize, name: &'static str) -> Result<(usize, usize), NtlmError> {
    let raw = message.get(at..at + 8).ok_or(NtlmError::Truncated {
        part: name,
        length: message.len(),
    })?;
    let length = usize::from(u16::from_le_bytes([raw[0], raw[1]]));
    let offset = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]) as usize;
    Ok((offset, length))
}

/// Reads the block a field descriptor points at, refusing one that points
/// outside the message.
fn field_bytes<'a>(
    message: &'a [u8],
    at: usize,
    name: &'static str,
) -> Result<&'a [u8], NtlmError> {
    let (offset, length) = field(message, at, name)?;
    message
        .get(offset..)
        .and_then(|rest| rest.get(..length))
        .ok_or(NtlmError::FieldOutOfRange {
            field: name,
            offset,
            length,
            message_length: message.len(),
        })
}

/// The `AV_PAIR` list a CHALLENGE carries in its `TargetInfo`.
///
/// The bytes are kept as they arrived. Nothing here re-encodes a pair it did
/// not change, because the list is mixed into the NTLMv2 response and a server
/// that re-derives the response computes it over what it sent.
#[derive(Clone, PartialEq, Eq)]
pub struct AvPairs {
    bytes: Vec<u8>,
    /// Where `MsvAvEOL` begins, which is where an appended pair goes.
    end: usize,
}

impl fmt::Debug for AvPairs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AvPairs")
            .field("len", &self.bytes.len())
            .finish()
    }
}

impl AvPairs {
    /// Validates a list and records where it ends.
    ///
    /// A list that runs past its buffer, or that never reaches `MsvAvEOL`, is
    /// refused. Both are reachable by an unauthenticated peer.
    pub fn parse(bytes: &[u8]) -> Result<Self, NtlmError> {
        let mut at = 0;
        loop {
            let header = bytes
                .get(at..at + 4)
                .ok_or(NtlmError::MalformedAvPairs(at))?;
            let id = u16::from_le_bytes([header[0], header[1]]);
            let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
            let end = at
                .checked_add(4)
                .and_then(|start| start.checked_add(length))
                .ok_or(NtlmError::MalformedAvPairs(at))?;
            if end > bytes.len() {
                return Err(NtlmError::MalformedAvPairs(at));
            }
            if id == AV_EOL {
                return Ok(Self {
                    bytes: bytes.to_vec(),
                    end: at,
                });
            }
            at = end;
        }
    }

    /// Walks the pairs ahead of `MsvAvEOL`.
    fn iter(&self) -> impl Iterator<Item = (u16, &[u8])> {
        let bytes = &self.bytes[..self.end];
        let mut at = 0;
        std::iter::from_fn(move || {
            let header = bytes.get(at..at + 4)?;
            let id = u16::from_le_bytes([header[0], header[1]]);
            let length = usize::from(u16::from_le_bytes([header[2], header[3]]));
            let value = bytes.get(at + 4..at + 4 + length)?;
            at += 4 + length;
            Some((id, value))
        })
    }

    /// The list up to and including `MsvAvEOL`.
    ///
    /// Anything a server put *after* the terminator is dropped rather than
    /// echoed: the NTLMv2 response is computed over these bytes, and carrying
    /// bytes past the end of the list back into it would let a peer choose
    /// content the client never read.
    fn as_sent(&self) -> &[u8] {
        &self.bytes[..self.end + 4]
    }

    /// The value of one pair, where the list carries it.
    pub fn get(&self, id: u16) -> Option<&[u8]> {
        self.iter().find(|(found, _)| *found == id).map(|(_, v)| v)
    }

    /// The server's own timestamp, where it sent one.
    ///
    /// [MS-NLMP] 3.1.5.1.2 has the client reuse it rather than its own clock,
    /// which is what makes the response resistant to a replay across a clock
    /// the client cannot see.
    pub fn timestamp(&self) -> Option<[u8; 8]> {
        self.get(AV_TIMESTAMP)?.try_into().ok()
    }

    /// The list as it goes into the NTLMv2 response: every pair the server
    /// sent, with `MsvAvFlags` saying a MIC follows, and `MsvAvEOL` last.
    ///
    /// This is reached only where the server sent a timestamp, which is the
    /// condition [MS-NLMP] 3.1.5.1.2 attaches the MIC to. Where it did not, the
    /// list travels back byte for byte as it arrived — which is also what makes
    /// the specification's own worked example reproducible, its challenge
    /// carrying no timestamp.
    fn with_mic_flag(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.end + 8 + 4);
        let mut had_flags = false;
        for (id, value) in self.iter() {
            out.extend_from_slice(&id.to_le_bytes());
            out.extend_from_slice(&(value.len() as u16).to_le_bytes());
            if id == AV_FLAGS && value.len() == 4 {
                had_flags = true;
                let existing = u32::from_le_bytes([value[0], value[1], value[2], value[3]]);
                out.extend_from_slice(&(existing | AV_FLAG_MIC_PROVIDED).to_le_bytes());
            } else {
                out.extend_from_slice(value);
            }
        }
        if !had_flags {
            out.extend_from_slice(&AV_FLAGS.to_le_bytes());
            out.extend_from_slice(&4u16.to_le_bytes());
            out.extend_from_slice(&AV_FLAG_MIC_PROVIDED.to_le_bytes());
        }
        out.extend_from_slice(&AV_EOL.to_le_bytes());
        out.extend_from_slice(&0u16.to_le_bytes());
        out
    }
}

/// The server's CHALLENGE message, parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Challenge {
    /// The flags the server agreed to.
    pub flags: u32,
    /// The eight-byte nonce the response is computed over.
    pub server_challenge: [u8; 8],
    /// The server's `TargetInfo`, which is mixed into the response verbatim.
    pub target_info: AvPairs,
    /// The message as it arrived. The MIC is computed over all three messages,
    /// so this one has to be kept whole.
    raw: Vec<u8>,
}

impl Challenge {
    /// Parses a CHALLENGE message.
    ///
    /// This runs before authentication has completed, on bytes an
    /// unauthenticated peer chose, and it is one of the crate's four fuzz
    /// targets for that reason.
    pub fn parse(message: &[u8]) -> Result<Self, NtlmError> {
        if message.len() < 12 || &message[..8] != SIGNATURE {
            return Err(NtlmError::NotNtlm);
        }
        let kind = u32::from_le_bytes([message[8], message[9], message[10], message[11]]);
        if kind != MESSAGE_CHALLENGE {
            return Err(NtlmError::UnexpectedMessageType {
                expected: MESSAGE_CHALLENGE,
                actual: kind,
            });
        }
        if message.len() < CHALLENGE_MIN_LEN {
            return Err(NtlmError::Truncated {
                part: "fixed fields",
                length: message.len(),
            });
        }
        let flags = u32::from_le_bytes([message[20], message[21], message[22], message[23]]);
        if flags & NEGOTIATE_EXTENDED_SESSIONSECURITY == 0 {
            return Err(NtlmError::NoExtendedSessionSecurity);
        }
        let mut server_challenge = [0u8; 8];
        server_challenge.copy_from_slice(&message[24..32]);

        // `TargetName` is read only to bound-check it: nothing in the exchange
        // depends on the name, and a descriptor pointing outside the message is
        // a malformed message however little this crate wants the field.
        field_bytes(message, 12, "TargetName")?;
        let target_info = AvPairs::parse(field_bytes(message, 40, "TargetInfo")?)?;

        Ok(Self {
            flags,
            server_challenge,
            target_info,
            raw: message.to_vec(),
        })
    }
}

/// The three values the client contributes to the AUTHENTICATE message that
/// come from neither the credentials nor the challenge: a nonce, a session key
/// and a clock reading.
///
/// They are separated from the message so a test can fix them. The [MS-NLMP]
/// worked example pins all three, which is what makes its expected bytes
/// reproducible exactly.
#[derive(Clone, PartialEq, Eq)]
pub struct ClientValues {
    /// The eight-byte client challenge, which goes into the response blob.
    pub client_challenge: [u8; 8],
    /// The session key exported under `NTLMSSP_NEGOTIATE_KEY_EXCH`.
    pub exported_session_key: [u8; DIGEST_LEN],
    /// The client's own clock as a FILETIME, used **only** where the server's
    /// `TargetInfo` carried no `MsvAvTimestamp`. Where it carried one, that is
    /// what goes into the response: [MS-NLMP] 3.1.5.1.2 has the client reuse
    /// the server's rather than its own, which is what makes the response
    /// resistant to a replay across a clock the client cannot see.
    pub timestamp: [u8; 8],
}

impl fmt::Debug for ClientValues {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The exported session key is key material. Its `Debug` says nothing.
        f.write_str("ClientValues(<redacted>)")
    }
}

impl ClientValues {
    /// Draws the two random values from the operating system's entropy source
    /// and the third from the clock.
    ///
    /// It is `getrandom` rather than `rand` because what is wanted is operating
    /// system entropy and not a pseudo-random generator seeded from it.
    pub fn fresh() -> Result<Self, getrandom::Error> {
        let mut client_challenge = [0u8; 8];
        let mut exported_session_key = [0u8; DIGEST_LEN];
        getrandom::fill(&mut client_challenge)?;
        getrandom::fill(&mut exported_session_key)?;
        Ok(Self {
            client_challenge,
            exported_session_key,
            timestamp: filetime_now(),
        })
    }
}

/// The AUTHENTICATE message, and the session key it exported.
#[derive(Clone, PartialEq, Eq)]
pub struct Authenticate {
    /// The message itself, which goes into the SPNEGO `responseToken`.
    pub message: Vec<u8>,
    /// The exported session key, which the SPNEGO `mechListMIC` is signed with.
    exported_session_key: [u8; DIGEST_LEN],
}

impl fmt::Debug for Authenticate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The message carries an offline-crackable NTLMv2 response and the
        // encrypted session key. Its `Debug` gives a length and nothing else.
        f.debug_struct("Authenticate")
            .field("len", &self.message.len())
            .finish()
    }
}

/// The current time as a FILETIME: 100-nanosecond ticks since 1601-01-01.
fn filetime_now() -> [u8; 8] {
    let unix_nanos = time::OffsetDateTime::now_utc().unix_timestamp_nanos();
    let ticks = unix_nanos / 100 + FILETIME_EPOCH_OFFSET;
    (ticks.clamp(0, i128::from(u64::MAX)) as u64).to_le_bytes()
}

/// Builds the AUTHENTICATE message that answers a CHALLENGE.
///
/// The `negotiate` argument is the NEGOTIATE message that opened the exchange.
/// It is not rebuilt here: the MIC is computed over all three messages, so the
/// bytes that actually went on the wire are the ones that have to be hashed.
pub fn authenticate(
    negotiate: &[u8],
    challenge: &Challenge,
    credentials: &Credentials,
    client_values: &ClientValues,
) -> Authenticate {
    let response_key = ntowf_v2(credentials);

    // **The MIC goes in exactly where [MS-NLMP] 3.1.5.1.2 puts it**: where the
    // server's `TargetInfo` carried a timestamp. Where it did not, the message
    // carries neither the `MsvAvFlags` claim nor the 16-byte field, and the AV
    // pairs travel back untouched — which is what a server that sent no
    // timestamp is expecting and what the specification's worked example
    // reproduces.
    let server_timestamp = challenge.target_info.timestamp();
    let with_mic = server_timestamp.is_some();
    let timestamp = server_timestamp.unwrap_or(client_values.timestamp);
    let header_len = if with_mic {
        MIC_OFFSET + DIGEST_LEN
    } else {
        AUTHENTICATE_HEADER_LEN
    };

    // `temp`, per [MS-NLMP] 3.3.2: the response version, six reserved bytes,
    // the timestamp, the client challenge, four more reserved bytes, the server's
    // AV pairs, and four bytes that close it.
    let av_pairs = if with_mic {
        challenge.target_info.with_mic_flag()
    } else {
        challenge.target_info.as_sent().to_vec()
    };
    let mut temp = Vec::with_capacity(28 + av_pairs.len() + 4);
    temp.extend_from_slice(&[1, 1, 0, 0, 0, 0, 0, 0]);
    temp.extend_from_slice(&timestamp);
    temp.extend_from_slice(&client_values.client_challenge);
    temp.extend_from_slice(&[0; 4]);
    temp.extend_from_slice(&av_pairs);
    temp.extend_from_slice(&[0; 4]);

    let mut proof_input = Vec::with_capacity(8 + temp.len());
    proof_input.extend_from_slice(&challenge.server_challenge);
    proof_input.extend_from_slice(&temp);
    let nt_proof = hmac_md5(&response_key, &proof_input);

    let mut nt_response = Vec::with_capacity(DIGEST_LEN + temp.len());
    nt_response.extend_from_slice(&nt_proof);
    nt_response.extend_from_slice(&temp);

    // For NTLMv2 the key exchange key is the session base key unchanged
    // ([MS-NLMP] 3.4.5.1), and `NTLMSSP_NEGOTIATE_KEY_EXCH` is what puts a key
    // of the client's own choosing under it.
    let key_exchange_key = hmac_md5(&response_key, &nt_proof);
    let mut encrypted_session_key = client_values.exported_session_key;
    rc4(&key_exchange_key, &mut encrypted_session_key);

    let domain = utf16(credentials.domain());
    let user = utf16(credentials.user());
    // The workstation is sent empty. See `Credentials`.
    let workstation: Vec<u8> = Vec::new();
    // NTLMv2 only: the LM response is the 24 zero bytes [MS-NLMP] 3.1.5.1.2
    // specifies where the client's challenge travels in the NT response.
    let lm_response = [0u8; 24];

    let mut message = vec![0u8; header_len];
    message[0..8].copy_from_slice(SIGNATURE);
    message[8..12].copy_from_slice(&MESSAGE_AUTHENTICATE.to_le_bytes());
    message[60..64].copy_from_slice(&NEGOTIATE_FLAGS.to_le_bytes());
    // 64..72 is `Version`, zero for the same reason it is zero in NEGOTIATE,
    // and 72..88 is the MIC where there is one — filled in below, once the
    // message is otherwise whole.

    // The payload order is [MS-NLMP] 2.2.1.3's own. An empty field's offset is
    // where it would have gone rather than zero, so every descriptor in the
    // message describes the same cursor.
    let mut payload = Vec::new();
    put_field(&mut message, 28, header_len, &mut payload, &domain);
    put_field(&mut message, 36, header_len, &mut payload, &user);
    put_field(&mut message, 44, header_len, &mut payload, &workstation);
    put_field(&mut message, 12, header_len, &mut payload, &lm_response);
    put_field(&mut message, 20, header_len, &mut payload, &nt_response);
    put_field(
        &mut message,
        52,
        header_len,
        &mut payload,
        &encrypted_session_key,
    );
    message.extend_from_slice(&payload);

    // [MS-NLMP] 3.1.5.1.2: the MIC is computed over the three messages with its
    // own field zeroed, which is what the zeroes already in place give.
    if with_mic {
        let mut mic_input =
            Vec::with_capacity(negotiate.len() + challenge.raw.len() + message.len());
        mic_input.extend_from_slice(negotiate);
        mic_input.extend_from_slice(&challenge.raw);
        mic_input.extend_from_slice(&message);
        let mic = hmac_md5(&client_values.exported_session_key, &mic_input);
        message[MIC_OFFSET..MIC_OFFSET + DIGEST_LEN].copy_from_slice(&mic);
    }

    Authenticate {
        message,
        exported_session_key: client_values.exported_session_key,
    }
}

impl Authenticate {
    /// The SPNEGO `mechListMIC` over the mechanism list the client offered.
    ///
    /// This is `GSS_GetMIC` with the NTLM client-to-server keys and sequence
    /// number zero: [MS-NLMP] 3.4.4.2's signature, whose checksum is encrypted
    /// under the sealing key because `NTLMSSP_NEGOTIATE_KEY_EXCH` is
    /// negotiated. `mech_list` is the DER `MechTypeList` — the `SEQUENCE` tag,
    /// its length and its contents — exactly as it appears inside the
    /// `NegTokenInit` the client sent.
    pub fn mech_list_mic(&self, mech_list: &[u8]) -> [u8; DIGEST_LEN] {
        const CLIENT_SIGNING: &[u8] =
            b"session key to client-to-server signing key magic constant\0";
        const CLIENT_SEALING: &[u8] =
            b"session key to client-to-server sealing key magic constant\0";

        let signing_key = magic_key(&self.exported_session_key, CLIENT_SIGNING);
        let sealing_key = magic_key(&self.exported_session_key, CLIENT_SEALING);

        let mut signed = Vec::with_capacity(4 + mech_list.len());
        signed.extend_from_slice(&0u32.to_le_bytes());
        signed.extend_from_slice(mech_list);
        let mut checksum = [0u8; 8];
        checksum.copy_from_slice(&hmac_md5(&signing_key, &signed)[..8]);
        rc4(&sealing_key, &mut checksum);

        let mut signature = [0u8; DIGEST_LEN];
        signature[0..4].copy_from_slice(&1u32.to_le_bytes());
        signature[4..12].copy_from_slice(&checksum);
        // The sequence number, which is zero and stays zero: this crate signs
        // exactly one thing.
        signature
    }
}

/// `SIGNKEY` and `SEALKEY` ([MS-NLMP] 3.4.5.2, 3.4.5.3), which differ only in
/// the constant they append. The full key goes in because
/// `NTLMSSP_NEGOTIATE_128` is negotiated.
fn magic_key(exported_session_key: &[u8; DIGEST_LEN], constant: &[u8]) -> [u8; DIGEST_LEN] {
    let mut hash = Md5::new();
    hash.update(exported_session_key);
    hash.update(constant);
    let mut key = [0u8; DIGEST_LEN];
    key.copy_from_slice(&hash.finalize());
    key
}

/// RC4 in place, which is used twice: for the encrypted session key and for the
/// `mechListMIC`'s checksum.
fn rc4(key: &[u8], buffer: &mut [u8]) {
    let mut cipher = <Rc4 as rc4::KeyInit>::new_from_slice(key).expect("RC4 takes 1..=256 bytes");
    cipher.apply_keystream(buffer);
}

/// Writes a field descriptor and appends its bytes to the payload.
fn put_field(
    message: &mut [u8],
    at: usize,
    header_len: usize,
    payload: &mut Vec<u8>,
    value: &[u8],
) {
    let offset = (header_len + payload.len()) as u32;
    let length = value.len() as u16;
    message[at..at + 2].copy_from_slice(&length.to_le_bytes());
    message[at + 2..at + 4].copy_from_slice(&length.to_le_bytes());
    message[at + 4..at + 8].copy_from_slice(&offset.to_le_bytes());
    payload.extend_from_slice(value);
}

/// UTF-16LE without a terminator, which is how NTLM carries a string.
fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_negotiate_message_carries_nine_flags_and_no_others() {
        let message = negotiate_message();
        let flags = u32::from_le_bytes([message[12], message[13], message[14], message[15]]);
        assert_eq!(flags, 0xE088_0215);
        assert_eq!(flags.count_ones(), 9);
        assert_eq!(flags & NEGOTIATE_ALWAYS_SIGN, 0);
        assert_eq!(flags & NEGOTIATE_VERSION, 0);
        assert_ne!(flags & NEGOTIATE_SIGN, 0);
        // The `Version` field is present and zero, which is what a message that
        // does not claim a version looks like.
        assert_eq!(&message[32..40], &[0u8; 8]);
    }

    #[test]
    fn av_pairs_that_run_past_their_buffer_are_refused() {
        // A pair declaring 16 bytes with 4 left.
        assert_eq!(
            AvPairs::parse(&[0x02, 0x00, 0x10, 0x00, 0, 0, 0, 0]),
            Err(NtlmError::MalformedAvPairs(0))
        );
        // A list that never reaches MsvAvEOL.
        assert_eq!(
            AvPairs::parse(&[0x02, 0x00, 0x00, 0x00]),
            Err(NtlmError::MalformedAvPairs(4))
        );
        assert!(AvPairs::parse(&[0x00, 0x00, 0x00, 0x00]).is_ok());
    }

    #[test]
    fn a_challenge_without_extended_session_security_is_refused() {
        let mut message = vec![0u8; CHALLENGE_MIN_LEN];
        message[0..8].copy_from_slice(SIGNATURE);
        message[8..12].copy_from_slice(&MESSAGE_CHALLENGE.to_le_bytes());
        assert_eq!(
            Challenge::parse(&message),
            Err(NtlmError::NoExtendedSessionSecurity)
        );
    }
}
