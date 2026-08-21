//! The wire tracer, and the one message whose bytes it will never write.
//!
//! **`SESSION_SETUP_ANDX`'s byte section is redacted unconditionally, and never
//! behind a feature flag.** The NTLMSSP token inside it carries an
//! offline-crackable NTLMv2 handshake, and a hex dump added while debugging a
//! wire problem would otherwise write a complete one to a log file. A rule that
//! can be switched off is a rule that will be, on the run where it matters.
//!
//! Credentials are not the only sensitive bytes a tracer sees. A dump of a
//! listing reply or a read reply carries filenames and file contents, which this
//! campaign's own corpus rules treat as sensitive enough to keep out of a
//! repository entirely. So byte-level dumping is off unless the operator turns
//! it on for a run — and the session setup stays redacted even when it is on.

use std::fmt;

use tracing::trace;

use super::header::{HEADER_LEN, command};

/// Which way a frame was travelling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Client to server.
    Outbound,
    /// Server to client.
    Inbound,
}

impl Direction {
    fn as_str(self) -> &'static str {
        match self {
            Direction::Outbound => "c2s",
            Direction::Inbound => "s2c",
        }
    }
}

/// Traces one SMB message, its NetBIOS header already stripped.
///
/// The header fields always go out. The bytes go out only when the operator has
/// switched dumping on for the run, and then only the part [`dumpable`] allows.
pub fn frame(direction: Direction, message: &[u8], dump_bytes: bool) {
    let Some(&command) = message.get(4) else {
        trace!(
            direction = direction.as_str(),
            length = message.len(),
            "frame shorter than an SMB header"
        );
        return;
    };
    let dumped = dumpable(message);
    trace!(
        direction = direction.as_str(),
        command = format_args!("{command:#04x}"),
        length = message.len(),
        redacted = dumped.len() != message.len(),
        bytes = %Hex(if dump_bytes { dumped } else { &[] }),
        "smb frame"
    );
}

/// The bytes of a message that may go into a dump.
///
/// A `SESSION_SETUP_ANDX` frame keeps its header — which carries the multiplex
/// id, the user id and the status a reader actually needs — and loses every
/// byte after it: the security blob and the NTLMSSP token inside it included.
/// Every other command keeps all of its bytes; the rule is about the one
/// message that carries a credential, not about tracing in general.
pub fn dumpable(message: &[u8]) -> &[u8] {
    match message.get(4) {
        Some(&command::SESSION_SETUP_ANDX) => &message[..HEADER_LEN.min(message.len())],
        _ => message,
    }
}

/// Hex, written straight into the trace line rather than through an allocation.
struct Hex<'a>(&'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The rule that matters is the one that holds with the switch *on*: with
    /// it off nothing is dumped anyway, so a redaction that only worked then
    /// would protect nothing.
    #[test]
    fn a_session_setup_dump_keeps_the_header_and_nothing_else() {
        let mut frame = vec![0xFFu8, b'S', b'M', b'B', command::SESSION_SETUP_ANDX];
        frame.resize(HEADER_LEN, 0);
        // The security blob, standing in for the NTLMSSP token.
        frame.extend_from_slice(b"NTLMSSP\0secret-material");
        let dumped = dumpable(&frame);
        assert_eq!(dumped.len(), HEADER_LEN);
        assert!(!dumped.windows(8).any(|window| window == b"NTLMSSP\0"));
    }

    #[test]
    fn every_other_command_dumps_whole() {
        let mut other = vec![0xFFu8, b'S', b'M', b'B', command::NEGOTIATE];
        other.resize(HEADER_LEN + 4, 0xAB);
        assert_eq!(dumpable(&other), &other[..]);
    }

    /// A frame too short to carry a command byte is traced rather than
    /// panicked over, because the tracer runs on bytes a peer chose.
    #[test]
    fn a_runt_frame_is_survivable() {
        super::frame(Direction::Inbound, &[0xFF, b'S', b'M', b'B'], true);
        assert_eq!(dumpable(&[0xFF, b'S']).len(), 2);
        let short_setup = [0xFFu8, b'S', b'M', b'B', command::SESSION_SETUP_ANDX];
        assert_eq!(dumpable(&short_setup), &short_setup[..]);
    }

    #[test]
    fn hex_writes_two_characters_a_byte() {
        assert_eq!(Hex(&[0x00, 0x0F, 0xFF]).to_string(), "000fff");
        assert_eq!(Hex(&[]).to_string(), "");
    }
}
