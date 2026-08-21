//! The AndX prologue, and the rule that this crate chains nothing.

use binrw::binrw;

use super::WireError;

/// The value of `AndXCommand` that says no further command follows.
pub const NO_FURTHER_COMMAND: u8 = 0xFF;

/// The four bytes an AndX-family command's word block opens with.
#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AndX {
    /// The next command in the chain, or [`NO_FURTHER_COMMAND`].
    pub command: u8,
    /// Reserved.
    pub reserved: u8,
    /// Where the next command's word block begins.
    ///
    /// It is read and ignored. It is emphatically **not** asserted zero beside
    /// the sentinel: five committed frames carry a non-zero offset with
    /// `AndXCommand = 0xFF`, and in every one the offset equals the SMB message
    /// length exactly, so a parser that seeks to it before checking the
    /// sentinel lands on the buffer boundary and the bug surfaces as an empty
    /// read rather than as a caught out-of-range seek.
    pub offset: u16,
}

impl AndX {
    /// The prologue this crate writes. It chains nothing.
    pub const NONE: Self = Self {
        command: NO_FURTHER_COMMAND,
        reserved: 0,
        offset: 0,
    };

    /// Refuses a response that chains another command.
    ///
    /// Nothing here can follow a chain, and after one the reader cannot trust
    /// where the next message begins, so this fails the connection rather than
    /// the request.
    pub fn refuse_chaining(self) -> Result<(), WireError> {
        if self.command == NO_FURTHER_COMMAND {
            Ok(())
        } else {
            Err(WireError::ChainedCommand(self.command))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_sentinel_is_what_says_there_is_no_next_command() {
        // The shape of `capture-win-b/0010-s2c-cmd75.bin`, whose `AndXOffset`
        // of 54 is the SMB message length exactly.
        let end_of_message = AndX {
            command: NO_FURTHER_COMMAND,
            reserved: 0,
            offset: 54,
        };
        assert!(end_of_message.refuse_chaining().is_ok());
        assert!(AndX::NONE.refuse_chaining().is_ok());
        assert!(matches!(
            AndX {
                command: 0x75,
                reserved: 0,
                offset: 0
            }
            .refuse_chaining(),
            Err(WireError::ChainedCommand(0x75))
        ));
    }
}
