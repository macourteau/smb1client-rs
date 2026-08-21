//! NetBIOS Session Service framing.
//!
//! Every SMB1 message travels inside a four-byte header: a message type, then a
//! length. The length is read as **17 bits** — the byte following the type
//! contributes its low bit as the length's high bit — which is what admits the
//! 130,108-byte read replies this crate asks for.
//!
//! Seventeen is a choice rather than a fact about the wire. Direct TCP framing
//! on port 445 reads that byte and the two after it as a 24-bit length, where
//! the NetBIOS session service treats the other seven bits as reserved. Reading
//! 17 and requiring those seven to be zero bounds the largest inbound frame at
//! 131,071 bytes; reading 24 would raise that bound to 16,777,215 for no
//! message this crate sends or expects.

use super::WireError;

/// The length of the NetBIOS Session Service header.
pub const HEADER_LEN: usize = 4;

/// The largest SMB message the 17-bit length field can describe.
pub const MAX_MESSAGE_LEN: usize = 0x0001_FFFF;

/// A session message, carrying one SMB message.
pub const TYPE_SESSION_MESSAGE: u8 = 0x00;

/// A keep-alive. It carries nothing and is consumed and discarded.
pub const TYPE_SESSION_KEEP_ALIVE: u8 = 0x85;

/// What a NetBIOS Session Service header announces.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageType {
    /// `0x00` — a session message. The length is the SMB message that follows.
    SessionMessage,
    /// `0x85` — a keep-alive, read off the socket and discarded.
    ///
    /// It is transport-level and reaches no request, which is the one exception
    /// to nothing being discarded silently.
    KeepAlive,
}

/// Reads a NetBIOS Session Service header.
///
/// Any message type other than `0x00` and `0x85` fails the connection: after
/// one the reader cannot tell where the next message begins.
pub fn decode_header(bytes: [u8; HEADER_LEN]) -> Result<(MessageType, usize), WireError> {
    let kind = match bytes[0] {
        TYPE_SESSION_MESSAGE => MessageType::SessionMessage,
        TYPE_SESSION_KEEP_ALIVE => MessageType::KeepAlive,
        other => return Err(WireError::UnknownNetbiosType(other)),
    };
    // Seven reserved bits, and a frame that sets one of them is refused rather
    // than read as a 24-bit length.
    if bytes[1] & 0xFE != 0 {
        return Err(WireError::ReservedNetbiosBits(bytes[1]));
    }
    let length = (usize::from(bytes[1] & 0x01) << 16)
        | usize::from(u16::from_be_bytes([bytes[2], bytes[3]]));
    Ok((kind, length))
}

/// Writes the NetBIOS Session Service header for a session message of `length`
/// bytes.
pub fn encode_header(length: usize) -> Result<[u8; HEADER_LEN], WireError> {
    if length > MAX_MESSAGE_LEN {
        return Err(WireError::MessageTooLong(length));
    }
    Ok([
        TYPE_SESSION_MESSAGE,
        ((length >> 16) & 0x01) as u8,
        ((length >> 8) & 0xFF) as u8,
        (length & 0xFF) as u8,
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn length_is_seventeen_bits() {
        // The bit that admits a frame past 65,535 bytes: 130,108 is the read
        // reply size this crate's chunk rule produces, and a 16-bit read of the
        // same header yields 64,572.
        assert_eq!(
            decode_header([0x00, 0x01, 0xFC, 0x3C]).unwrap(),
            (MessageType::SessionMessage, 130_108)
        );
        assert_eq!(
            decode_header([0x00, 0x01, 0xFF, 0xFF]).unwrap(),
            (MessageType::SessionMessage, MAX_MESSAGE_LEN)
        );
    }

    #[test]
    fn the_other_seven_bits_are_refused() {
        // Read as a 24-bit length this is 131,072. Refused instead.
        assert!(matches!(
            decode_header([0x00, 0x02, 0x00, 0x00]),
            Err(WireError::ReservedNetbiosBits(0x02))
        ));
        assert!(matches!(
            decode_header([0x00, 0x80, 0x00, 0x00]),
            Err(WireError::ReservedNetbiosBits(0x80))
        ));
    }

    #[test]
    fn keep_alive_is_a_type_of_its_own_and_anything_else_fails() {
        assert_eq!(
            decode_header([0x85, 0x00, 0x00, 0x00]).unwrap(),
            (MessageType::KeepAlive, 0)
        );
        assert!(matches!(
            decode_header([0x81, 0x00, 0x00, 0x44]),
            Err(WireError::UnknownNetbiosType(0x81))
        ));
    }

    #[test]
    fn header_round_trips_through_the_high_bit() {
        for length in [0, 1, 39, 16_640, 65_535, 65_536, 130_108, MAX_MESSAGE_LEN] {
            let header = encode_header(length).unwrap();
            assert_eq!(
                decode_header(header).unwrap(),
                (MessageType::SessionMessage, length)
            );
        }
        assert!(matches!(
            encode_header(MAX_MESSAGE_LEN + 1),
            Err(WireError::MessageTooLong(_))
        ));
    }
}
