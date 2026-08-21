//! SPNEGO, written from RFC 4178.
//!
//! **DER out, lenient BER in.** The client emits definite-length,
//! minimally-encoded DER; the decoder accepts the indefinite lengths real
//! servers emit, because they do.
//!
//! The tokens are hand-rolled rather than decoded through a general ASN.1
//! crate. The grammar the client exchanges is closed and tiny — three shapes
//! cover the whole exchange at its longest — and a general decoder is a larger
//! attack surface for a parser an unauthenticated peer reaches before
//! authentication has completed.
//!
//! Three shapes, and no more:
//!
//! 1. **encoded** — the `NegTokenInit` the client sends, inside its GSS-API
//!    `initialContextToken` wrapper, carrying `mechTypes` of NTLMSSP alone and
//!    the NTLM NEGOTIATE message as `mechToken`;
//! 2. **decoded** — the `NegTokenResp` the server returns, carrying the NTLM
//!    CHALLENGE as `responseToken`;
//! 3. **encoded** — the `NegTokenResp` the client sends back, carrying the NTLM
//!    AUTHENTICATE message as `responseToken` and the `mechListMIC`, with the
//!    GSS-API wrapper stripped rather than emitted.
//!
//! The `NegTokenInit2` a server puts in its *negotiate* response is not among
//! them: nothing in the exchange depends on it and this crate does not parse
//! it.
//!
//! **The exchange can also end after the first leg**, in which case shapes 2
//! and 3 are never exchanged at all — see [`crate::session`], which is where
//! that path is decided.

/// `[APPLICATION 0]` — the GSS-API `initialContextToken` wrapper.
const TAG_APPLICATION_0: u8 = 0x60;
/// `OBJECT IDENTIFIER`.
const TAG_OID: u8 = 0x06;
/// `OCTET STRING`.
const TAG_OCTET_STRING: u8 = 0x04;
/// `SEQUENCE`.
const TAG_SEQUENCE: u8 = 0x30;
/// `[0]` — `negTokenInit` in the `NegotiationToken` choice, and `mechTypes`
/// and `negState` inside the two tokens.
const TAG_CONTEXT_0: u8 = 0xA0;
/// `[1]` — `negTokenResp`, and `supportedMech`.
const TAG_CONTEXT_1: u8 = 0xA1;
/// `[2]` — `mechToken` and `responseToken`.
const TAG_CONTEXT_2: u8 = 0xA2;
/// `[3]` — `mechListMIC`.
const TAG_CONTEXT_3: u8 = 0xA3;

/// The SPNEGO mechanism OID, `1.3.6.1.5.5.2`, DER-encoded.
const SPNEGO_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x05, 0x05, 0x02];
/// The NTLMSSP mechanism OID, `1.3.6.1.4.1.311.2.2.10`, DER-encoded.
const NTLMSSP_OID: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A];

/// How deep the decoder will follow nested constructed values.
///
/// The grammar is three levels deep and this is well above it. It exists so a
/// peer cannot drive the decoder's recursion with a token of its own choosing.
const MAX_DEPTH: usize = 16;

/// What can go wrong reading a server's SPNEGO token.
///
/// Every variant is reachable by an unauthenticated peer.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SpnegoError {
    /// A value's declared length runs past the end of the buffer, or a tag or
    /// length ran out mid-way.
    #[error("SPNEGO token is truncated at byte {0}")]
    Truncated(usize),

    /// A length whose long form declares more bytes than a `usize` holds. A
    /// token that big is not one this crate could have received.
    #[error("SPNEGO token declares a length this crate cannot represent")]
    LengthTooLarge,

    /// The tag at this position was not the one the grammar allows.
    #[error("SPNEGO token carries tag {actual:#04x} where {expected:#04x} was expected")]
    UnexpectedTag {
        /// What the grammar allows here.
        expected: u8,
        /// What arrived.
        actual: u8,
    },

    /// An indefinite-length value that never reached its end-of-contents pair.
    #[error("SPNEGO token opens an indefinite length that never ends")]
    UnterminatedIndefinite,

    /// The token nested deeper than the grammar can.
    #[error("SPNEGO token nests deeper than {MAX_DEPTH} levels")]
    TooDeep,

    /// A `NegTokenResp` carrying no `responseToken`, where the exchange needs
    /// one.
    #[error("the server's SPNEGO token carries no responseToken")]
    NoResponseToken,
}

/// A tag-length-value read out of a buffer.
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    /// How many bytes of the input the whole tag-length-value consumed.
    consumed: usize,
}

/// Reads one tag-length-value, accepting both definite and indefinite lengths.
///
/// The indefinite form is why this decodes BER rather than DER: real servers
/// emit it, and a strict DER reader refuses tokens that authenticate perfectly
/// well.
fn read_tlv(bytes: &[u8], depth: usize) -> Result<Tlv<'_>, SpnegoError> {
    if depth > MAX_DEPTH {
        return Err(SpnegoError::TooDeep);
    }
    let tag = *bytes.first().ok_or(SpnegoError::Truncated(0))?;
    let first = *bytes.get(1).ok_or(SpnegoError::Truncated(1))?;

    if first == 0x80 {
        // Indefinite: the value runs to an end-of-contents pair at this level.
        let body = &bytes[2..];
        let mut at = 0;
        loop {
            match body.get(at..at + 2) {
                Some([0x00, 0x00]) => {
                    return Ok(Tlv {
                        tag,
                        value: &body[..at],
                        consumed: 2 + at + 2,
                    });
                }
                Some(_) => {
                    let inner = read_tlv(&body[at..], depth + 1)?;
                    at += inner.consumed;
                }
                None => return Err(SpnegoError::UnterminatedIndefinite),
            }
        }
    }

    let (length, header) = if first & 0x80 == 0 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7F);
        if count == 0 || count > core::mem::size_of::<usize>() {
            return Err(SpnegoError::LengthTooLarge);
        }
        let raw = bytes.get(2..2 + count).ok_or(SpnegoError::Truncated(2))?;
        let mut length = 0usize;
        for &byte in raw {
            length = (length << 8) | usize::from(byte);
        }
        (length, 2 + count)
    };

    let value = bytes
        .get(header..)
        .and_then(|rest| rest.get(..length))
        .ok_or(SpnegoError::Truncated(header))?;
    Ok(Tlv {
        tag,
        value,
        consumed: header + length,
    })
}

/// Reads one tag-length-value and refuses a tag the grammar does not allow.
fn expect(bytes: &[u8], tag: u8, depth: usize) -> Result<Tlv<'_>, SpnegoError> {
    let tlv = read_tlv(bytes, depth)?;
    if tlv.tag != tag {
        return Err(SpnegoError::UnexpectedTag {
            expected: tag,
            actual: tlv.tag,
        });
    }
    Ok(tlv)
}

/// Writes a definite-length header in the shortest form that carries it, which
/// is what DER requires.
fn put_tlv(out: &mut Vec<u8>, tag: u8, value: &[u8]) {
    out.push(tag);
    let length = value.len();
    if length < 0x80 {
        out.push(length as u8);
    } else {
        let bytes = length.to_be_bytes();
        let leading = bytes.iter().take_while(|&&b| b == 0).count();
        let significant = &bytes[leading..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(value);
}

/// The DER `MechTypeList` this client offers: NTLMSSP alone.
///
/// It is public because the `mechListMIC` is computed over exactly these
/// bytes — the `SEQUENCE` tag, its length and its contents — so the two have to
/// agree by construction rather than by two encoders happening to match.
pub fn mech_list() -> Vec<u8> {
    let mut oid = Vec::new();
    put_tlv(&mut oid, TAG_OID, NTLMSSP_OID);
    let mut list = Vec::new();
    put_tlv(&mut list, TAG_SEQUENCE, &oid);
    list
}

/// The `NegTokenInit` the client sends in its first `SESSION_SETUP_ANDX`,
/// inside its GSS-API wrapper.
pub fn neg_token_init(mech_token: &[u8]) -> Vec<u8> {
    let mut init = Vec::new();
    put_tlv(&mut init, TAG_CONTEXT_0, &mech_list());
    let mut token = Vec::new();
    put_tlv(&mut token, TAG_OCTET_STRING, mech_token);
    put_tlv(&mut init, TAG_CONTEXT_2, &token);

    let mut sequence = Vec::new();
    put_tlv(&mut sequence, TAG_SEQUENCE, &init);

    let mut inner = Vec::new();
    put_tlv(&mut inner, TAG_OID, SPNEGO_OID);
    put_tlv(&mut inner, TAG_CONTEXT_0, &sequence);

    let mut out = Vec::new();
    put_tlv(&mut out, TAG_APPLICATION_0, &inner);
    out
}

/// The `NegTokenResp` the client sends back, carrying the AUTHENTICATE message
/// and the `mechListMIC`.
///
/// The GSS-API wrapper is stripped rather than emitted: only the first token of
/// a context establishment carries one.
pub fn neg_token_resp(response_token: &[u8], mech_list_mic: &[u8]) -> Vec<u8> {
    let mut fields = Vec::new();
    let mut token = Vec::new();
    put_tlv(&mut token, TAG_OCTET_STRING, response_token);
    put_tlv(&mut fields, TAG_CONTEXT_2, &token);
    let mut mic = Vec::new();
    put_tlv(&mut mic, TAG_OCTET_STRING, mech_list_mic);
    put_tlv(&mut fields, TAG_CONTEXT_3, &mic);

    let mut sequence = Vec::new();
    put_tlv(&mut sequence, TAG_SEQUENCE, &fields);

    let mut out = Vec::new();
    put_tlv(&mut out, TAG_CONTEXT_1, &sequence);
    out
}

/// The `responseToken` out of the `NegTokenResp` a server answers with.
///
/// `negState` and `supportedMech` are read past rather than acted on: the NTLM
/// message inside is what decides whether the exchange continues, and a
/// `negState` disagreeing with it would tell this crate nothing it could act
/// on. A GSS-API wrapper is accepted around the token as well as absent,
/// because nothing in the specification forbids a server sending one.
///
/// This is one of the crate's four fuzz targets: it runs before authentication
/// has completed, on bytes an unauthenticated peer chose.
pub fn response_token(token: &[u8]) -> Result<Vec<u8>, SpnegoError> {
    let outer = read_tlv(token, 0)?;
    let body = if outer.tag == TAG_APPLICATION_0 {
        // A wrapped token: skip the SPNEGO OID and take what follows.
        let oid = expect(outer.value, TAG_OID, 1)?;
        &outer.value[oid.consumed..]
    } else {
        token
    };

    let negotiation = expect(body, TAG_CONTEXT_1, 1)?;
    let sequence = expect(negotiation.value, TAG_SEQUENCE, 2)?;

    let mut rest = sequence.value;
    while !rest.is_empty() {
        let field = read_tlv(rest, 3)?;
        if field.tag == TAG_CONTEXT_2 {
            let octets = expect(field.value, TAG_OCTET_STRING, 4)?;
            return Ok(octets.value.to_vec());
        }
        if !matches!(
            field.tag,
            TAG_CONTEXT_0 | TAG_CONTEXT_1 | TAG_CONTEXT_2 | TAG_CONTEXT_3
        ) {
            return Err(SpnegoError::UnexpectedTag {
                expected: TAG_CONTEXT_2,
                actual: field.tag,
            });
        }
        rest = &rest[field.consumed..];
    }
    Err(SpnegoError::NoResponseToken)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_mech_list_is_the_bytes_the_mic_is_computed_over() {
        assert_eq!(
            mech_list(),
            vec![
                0x30, 0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x02, 0x0A
            ]
        );
    }

    #[test]
    fn a_long_form_length_is_written_in_the_shortest_form_that_carries_it() {
        let mut out = Vec::new();
        put_tlv(&mut out, TAG_OCTET_STRING, &[0u8; 200]);
        assert_eq!(&out[..3], &[0x04, 0x81, 0xC8]);
        let mut out = Vec::new();
        put_tlv(&mut out, TAG_OCTET_STRING, &vec![0u8; 300]);
        assert_eq!(&out[..4], &[0x04, 0x82, 0x01, 0x2C]);
        let mut out = Vec::new();
        put_tlv(&mut out, TAG_OCTET_STRING, &[0u8; 127]);
        assert_eq!(&out[..2], &[0x04, 0x7F]);
    }

    /// A `NegTokenResp` written with indefinite lengths at every level, which
    /// is what a strict DER reader would refuse and a real server may send.
    #[test]
    fn indefinite_lengths_decode() {
        let mut inner = vec![TAG_CONTEXT_2, 0x80];
        inner.extend_from_slice(&[TAG_OCTET_STRING, 0x03, 1, 2, 3]);
        inner.extend_from_slice(&[0x00, 0x00]);

        let mut sequence = vec![TAG_SEQUENCE, 0x80];
        sequence.extend_from_slice(&[TAG_CONTEXT_0, 0x03, 0x0A, 0x01, 0x01]);
        sequence.extend_from_slice(&inner);
        sequence.extend_from_slice(&[0x00, 0x00]);

        let mut token = vec![TAG_CONTEXT_1, 0x80];
        token.extend_from_slice(&sequence);
        token.extend_from_slice(&[0x00, 0x00]);

        assert_eq!(response_token(&token).unwrap(), vec![1, 2, 3]);
    }

    #[test]
    fn a_token_that_declares_more_than_it_carries_is_refused() {
        assert!(matches!(
            response_token(&[TAG_CONTEXT_1, 0x40, 0x30, 0x02]),
            Err(SpnegoError::Truncated(_))
        ));
        assert_eq!(
            response_token(&[TAG_CONTEXT_1, 0x80]),
            Err(SpnegoError::UnterminatedIndefinite)
        );
    }
}
