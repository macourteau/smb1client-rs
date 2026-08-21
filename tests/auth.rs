//! What CI asserts for `auth/`.
//!
//! Session-setup frames are excluded from the fixture corpus by rule — they
//! carry an offline-crackable NTLMv2 handshake — and they are the only place
//! NTLM and SPNEGO appear on the wire, so these two modules can have no
//! captured coverage of their own. Two committed vector files stand in:
//!
//! - `vectors/ms-nlmp-ntlmv2.txt`, the [MS-NLMP] worked example, which fixes
//!   the nonce and the timestamp so the expected bytes are reproducible
//!   exactly, carries no real credential, and comes from the specification
//!   rather than from the reference library's source — the same independence
//!   the licensing rule asks of the implementation;
//! - `vectors/reference-cross-check.txt`, the behavioural comparison against
//!   the reference library at `b948f59`, run against a scripted server so it
//!   too carries only the specification's credentials.

use std::collections::HashMap;

use smb1client::Credentials;
use smb1client::auth::ntlm::{self, Challenge, ClientValues};
use smb1client::auth::spnego;

/// Reads a `name = hex` vector file.
fn vectors(name: &str) -> HashMap<String, String> {
    let path = format!("{}/tests/vectors/{name}", env!("CARGO_MANIFEST_DIR"));
    let text = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    text.lines()
        .filter_map(|line| line.split('#').next())
        .filter_map(|line| line.split_once(" = "))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect()
}

fn bytes(vectors: &HashMap<String, String>, name: &str) -> Vec<u8> {
    let hex = vectors
        .get(name)
        .unwrap_or_else(|| panic!("vector {name} is missing"));
    hex::decode(hex).unwrap_or_else(|e| panic!("vector {name}: {e}"))
}

fn text<'a>(vectors: &'a HashMap<String, String>, name: &str) -> &'a str {
    vectors
        .get(name)
        .unwrap_or_else(|| panic!("vector {name} is missing"))
}

/// A field descriptor out of an AUTHENTICATE message: length, then offset.
fn field(message: &[u8], at: usize) -> &[u8] {
    let length = usize::from(u16::from_le_bytes([message[at], message[at + 1]]));
    let offset = u32::from_le_bytes([
        message[at + 4],
        message[at + 5],
        message[at + 6],
        message[at + 7],
    ]) as usize;
    &message[offset..offset + length]
}

const LM_RESPONSE: usize = 12;
const NT_RESPONSE: usize = 20;
const SESSION_KEY: usize = 52;
const FLAGS: usize = 60;

/// The whole NTLMv2 pipeline against the specification's own worked example.
///
/// What is asserted byte for byte against [MS-NLMP] is everything the
/// cryptography produces: the response key, the blob, the proof and the
/// encrypted session key. The message around them differs in four documented
/// places, and the vector file names each.
#[test]
fn the_ms_nlmp_worked_example_is_reproduced() {
    let vectors = vectors("ms-nlmp-ntlmv2.txt");
    let credentials = Credentials::new(text(&vectors, "user"), text(&vectors, "password"))
        .with_domain(text(&vectors, "domain"));

    let challenge = Challenge::parse(&bytes(&vectors, "challenge_message")).unwrap();
    assert_eq!(
        challenge.server_challenge.as_slice(),
        bytes(&vectors, "server_challenge")
    );
    // The example's `Time` is zero and its challenge carries no
    // `MsvAvTimestamp`, which is what puts the AUTHENTICATE message on the
    // no-MIC shape.
    assert_eq!(challenge.target_info.timestamp(), None);

    let mut client_challenge = [0u8; 8];
    client_challenge.copy_from_slice(&bytes(&vectors, "client_challenge"));
    let mut exported_session_key = [0u8; 16];
    exported_session_key.copy_from_slice(&bytes(&vectors, "random_session_key"));
    let mut timestamp = [0u8; 8];
    timestamp.copy_from_slice(&bytes(&vectors, "time"));
    let client_values = ClientValues {
        client_challenge,
        exported_session_key,
        timestamp,
    };

    let authenticate = ntlm::authenticate(
        &ntlm::negotiate_message(),
        &challenge,
        &credentials,
        &client_values,
    );
    let message = &authenticate.message;

    // The two values the specification computes, byte for byte.
    assert_eq!(
        field(message, NT_RESPONSE),
        bytes(&vectors, "nt_challenge_response"),
        "NtChallengeResponse must match [MS-NLMP] 4.2.4.2.2"
    );
    assert_eq!(
        field(message, NT_RESPONSE)[..16],
        bytes(&vectors, "nt_proof_str")[..],
        "the NTProofStr is the first sixteen bytes of it"
    );
    assert_eq!(
        field(message, NT_RESPONSE)[16..],
        bytes(&vectors, "temp")[..],
        "and `temp` is the rest"
    );
    assert_eq!(
        field(message, SESSION_KEY),
        bytes(&vectors, "encrypted_session_key"),
        "EncryptedRandomSessionKey must match [MS-NLMP] 4.2.4.2.3"
    );

    // NTLMv2 only: the LM response is twenty-four zero bytes and is emphatically
    // not the LMv2 response the example carries.
    assert_eq!(field(message, LM_RESPONSE), [0u8; 24]);
    assert_ne!(
        field(message, LM_RESPONSE),
        bytes(&vectors, "lmv2_response")
    );

    assert_eq!(
        u32::from_le_bytes(message[FLAGS..FLAGS + 4].try_into().unwrap()),
        ntlm::NEGOTIATE_FLAGS
    );
    // No MIC field at all on this shape: the payload begins at 72, where a
    // message carrying one begins at 88.
    assert_eq!(field(message, LM_RESPONSE).len(), 24);
    assert_eq!(message.len(), 216);

    assert_eq!(
        message.as_slice(),
        bytes(&vectors, "port_authenticate_message"),
        "the whole message is pinned so a change to any part of it is visible"
    );
}

/// The nine flags, enumerated from [MS-NLMP] 2.2.2.5 and asserted as a set.
///
/// A test on the constant alone would pass a message that carried something
/// else, so this reads the bytes the NEGOTIATE message actually puts on the
/// wire.
#[test]
fn the_negotiate_message_carries_the_nine_flags() {
    let message = ntlm::negotiate_message();
    let flags = u32::from_le_bytes(message[12..16].try_into().unwrap());

    let expected = ntlm::NEGOTIATE_UNICODE
        | ntlm::REQUEST_TARGET
        | ntlm::NEGOTIATE_SIGN
        | ntlm::NEGOTIATE_NTLM
        | ntlm::NEGOTIATE_EXTENDED_SESSIONSECURITY
        | ntlm::NEGOTIATE_TARGET_INFO
        | ntlm::NEGOTIATE_128
        | ntlm::NEGOTIATE_KEY_EXCH
        | ntlm::NEGOTIATE_56;
    assert_eq!(flags, expected);
    assert_eq!(flags.count_ones(), 9);

    // The two the reference sends and this crate does not.
    assert_eq!(flags & ntlm::NEGOTIATE_ALWAYS_SIGN, 0);
    assert_eq!(flags & ntlm::NEGOTIATE_VERSION, 0);
    // And the one whose removal makes Windows refuse authentication outright.
    assert_ne!(flags & ntlm::NEGOTIATE_SIGN, 0);
}

/// The behavioural cross-check: the same inputs through both implementations,
/// and the bytes compared.
#[test]
fn the_reference_library_agrees_on_every_value_the_two_share() {
    let vectors = vectors("reference-cross-check.txt");
    let credentials = Credentials::new(text(&vectors, "user"), text(&vectors, "password"))
        .with_domain(text(&vectors, "domain"));

    // The DER the mechListMIC is computed over.
    assert_eq!(spnego::mech_list(), bytes(&vectors, "reference_mech_list"));

    // The SPNEGO encoders, byte for byte. Given the reference's own NTLM
    // messages, the port must produce the reference's own tokens: what is being
    // compared is the encoder and nothing else.
    assert_eq!(
        spnego::neg_token_init(&bytes(&vectors, "reference_negotiate_message")),
        bytes(&vectors, "reference_neg_token_init")
    );
    assert_eq!(
        spnego::neg_token_resp(
            &bytes(&vectors, "reference_authenticate_message"),
            &bytes(&vectors, "reference_mech_list_mic"),
        ),
        bytes(&vectors, "reference_neg_token_resp")
    );

    let mut client_challenge = [0u8; 8];
    client_challenge.copy_from_slice(&bytes(&vectors, "client_challenge"));
    let mut exported_session_key = [0u8; 16];
    exported_session_key.copy_from_slice(&bytes(&vectors, "exported_session_key"));
    let client_values = ClientValues {
        client_challenge,
        exported_session_key,
        // Both challenges below carry a timestamp, so this is never reached and
        // is fixed only so the vector cannot depend on the clock.
        timestamp: [0; 8],
    };

    // The NTLMv2 core, over the reference's own blob. The AV pair list the
    // reference built is handed back as a challenge's `TargetInfo`, so both
    // sides assemble the identical `temp` and what the equality compares is the
    // cryptography rather than which pairs each side chose to add.
    let shared =
        Challenge::parse(&bytes(&vectors, "challenge_carrying_reference_av_pairs")).unwrap();
    let over_shared = ntlm::authenticate(
        &bytes(&vectors, "reference_negotiate_message"),
        &shared,
        &credentials,
        &client_values,
    );
    assert_eq!(
        field(&over_shared.message, NT_RESPONSE)[16..],
        bytes(&vectors, "reference_temp")[..],
        "the port must assemble the reference's own blob from it"
    );
    assert_eq!(
        field(&over_shared.message, NT_RESPONSE)[..16],
        bytes(&vectors, "reference_nt_proof_str")[..],
        "and compute the reference's own NTProofStr over it"
    );

    // The mechListMIC, which is the whole of SIGNKEY, SEALKEY, the HMAC and the
    // RC4 that encrypts the checksum — on a session key the reference drew.
    assert_eq!(
        over_shared.mech_list_mic(&spnego::mech_list()),
        bytes(&vectors, "reference_mech_list_mic")[..],
        "the mechListMIC must match the reference's byte for byte"
    );

    // And the message the port builds from the scripted challenge, pinned. It
    // differs from the reference's deliberately; what this holds is the MIC and
    // every field around it against a value computed independently of this code.
    let scripted = Challenge::parse(&bytes(&vectors, "challenge_message")).unwrap();
    assert!(scripted.target_info.timestamp().is_some());
    let over_scripted = ntlm::authenticate(
        &ntlm::negotiate_message(),
        &scripted,
        &credentials,
        &client_values,
    );
    assert_eq!(
        over_scripted.message,
        bytes(&vectors, "port_authenticate_message")
    );
    // The timestamp path is the one that carries a MIC, so the payload begins
    // sixteen bytes later than it does on the specification's example.
    assert_ne!(&over_scripted.message[72..88], &[0u8; 16]);

    // The decoder, on the token the reference actually received.
    let init = bytes(&vectors, "reference_neg_token_init");
    assert!(
        spnego::response_token(&init).is_err(),
        "a NegTokenInit is not a NegTokenResp"
    );
    assert_eq!(
        spnego::response_token(&bytes(&vectors, "reference_neg_token_resp")).unwrap(),
        bytes(&vectors, "reference_authenticate_message")
    );
}

/// A redacted `Debug` is exactly what a later `#[derive(Debug)]` silently
/// undoes, so the secret's absence from the formatted output is asserted rather
/// than assumed.
#[test]
fn credentials_never_reach_a_formatted_string() {
    let secret = "correct-horse-battery-staple";
    let credentials = Credentials::new("smbtest", secret).with_domain("WORKGROUP");

    let debug = format!("{credentials:?}");
    assert!(
        !debug.contains(secret),
        "Debug leaked the password: {debug}"
    );
    assert!(debug.contains("redacted"), "{debug}");
    // What a caller does need is still there.
    assert!(debug.contains("smbtest"));
    assert!(debug.contains("WORKGROUP"));

    let password = smb1client::Password::new(secret);
    let debug = format!("{password:?}");
    assert!(
        !debug.contains(secret),
        "Debug leaked the password: {debug}"
    );

    // The exported session key is key material too, and so is everything the
    // AUTHENTICATE message carries.
    let client_values = ClientValues {
        client_challenge: [0xAA; 8],
        exported_session_key: [0x55; 16],
        timestamp: [0; 8],
    };
    let debug = format!("{client_values:?}");
    assert!(
        !debug.contains("55"),
        "Debug leaked the session key: {debug}"
    );

    let vectors = vectors("ms-nlmp-ntlmv2.txt");
    let challenge = Challenge::parse(&bytes(&vectors, "challenge_message")).unwrap();
    let authenticate = ntlm::authenticate(
        &ntlm::negotiate_message(),
        &challenge,
        &Credentials::new("User", "Password").with_domain("Domain"),
        &client_values,
    );
    let debug = format!("{authenticate:?}");
    assert!(
        !debug.contains(&hex::encode(&authenticate.message)),
        "Debug leaked the AUTHENTICATE message: {debug}"
    );
    assert!(!debug.contains("68cd0ab8"), "{debug}");
}
