//! `SMB_COM_ECHO`, which the connection cache's liveness probe sends and
//! nothing else does.
//!
//! **This encoder has no oracle.** The reference library sends no echo at all —
//! its `HealthCheck` hook is nil by default and the `sendEcho` its own
//! documentation calls does not exist in it — and no fixture in the corpus
//! carries one. So the shape here is written from [MS-CIFS] and the probe's
//! purpose, and what it says is on the conformance script rather than proven
//! against a captured frame.
//!
//! **`EchoCount` is 1, and that is forced rather than chosen.** The server
//! answers with as many replies as the count asks for, all on the one multiplex
//! id; the connection layer routes one completed transaction per id and fails
//! the connection on a frame that routes to no request, so at any count above
//! one every reply after the first would kill the connection the probe exists
//! to vouch for.
//!
//! The byte area is empty. That field carries the bytes the server is asked to
//! echo back, and the probe has nothing to say: it treats any successful reply
//! as the signal it wanted and reads nothing out of what comes back.

use binrw::binrw;

use super::{WireError, body, write_words};

/// The only `EchoCount` this crate sends, for the reason the module
/// documentation gives.
pub const PROBE_ECHO_COUNT: u16 = 1;

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EchoWords {
    echo_count: u16,
}

/// `SMB_COM_ECHO`, as the liveness probe sends it.
///
/// The header it travels under carries `UID = 0` and `TID = 0xFFFF` — no
/// session and no tree — because the probe asks whether the transport and the
/// server's SMB layer are alive, not whether any session or tree still is. The
/// header is the connection's to build, so those two are the caller's to set on
/// the request rather than fields here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EchoRequest {
    /// How many replies the server is asked for.
    pub echo_count: u16,
}

impl EchoRequest {
    /// The probe's own request: one reply, and nothing to echo back.
    pub fn probe() -> Self {
        Self {
            echo_count: PROBE_ECHO_COUNT,
        }
    }

    /// Encodes the command body.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        Ok(body(
            &write_words(&EchoWords {
                echo_count: self.echo_count,
            })?,
            &[],
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The whole of the probe's body, byte for byte. Nothing else pins it: no
    /// server in the corpus was ever sent one, so this test is the only place
    /// the three values the design fixes — a `WordCount` of 1, an `EchoCount`
    /// of 1 and an empty byte area — are held to.
    #[test]
    fn the_probe_asks_for_one_reply_and_echoes_nothing() {
        let body = EchoRequest::probe().encode_body().expect("an echo encodes");
        // `WordCount = 1`, `EchoCount = 1`, `ByteCount = 0`.
        assert_eq!(body, vec![0x01, 0x01, 0x00, 0x00, 0x00]);
    }
}
