//! Session-scoped commands.
//!
//! `SMB_COM_SESSION_SETUP_ANDX` is not here: it carries the SPNEGO exchange and
//! arrives with the authentication modules.

use binrw::binrw;

use super::andx::AndX;
use super::header::command;
use super::{Message, WireError, body, read_words, write_words};

/// The `WordCount` of a logoff in either direction.
const LOGOFF_WORDS: u8 = 2;

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
