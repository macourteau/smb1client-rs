//! RAP's `NetShareEnum`, at information level 1, over `\PIPE\LANMAN`.
//!
//! RAP predates DCE/RPC and is one round trip rather than four, which is why it
//! is tried first. It is also the path Windows does not serve at all: a request
//! with nothing wrong with it is answered `STATUS_NOT_SUPPORTED`, which is what
//! makes the fall-through to `srvsvc` required rather than defensive.
//!
//! The transaction that carries it is built by the wire layer, whose
//! [`TransactionRequest::rap`] pins the `SetupCount` and the `Name`
//! spelling this path depends on.
//!
//! [`TransactionRequest::rap`]: crate::wire::transaction::TransactionRequest::rap

use super::{Share, ShareKind};

/// `NetShareEnum`.
const FUNCTION: u16 = 0x0000;

/// The descriptor of the parameters the two sides exchange: a level and a
/// receive buffer size out, a converter, an entry count and an available count
/// back.
const PARAMETER_DESCRIPTOR: &[u8] = b"WrLeh\0";

/// The descriptor of one level 1 entry: a 13-byte name, a pad byte, a 16-bit
/// type and a pointer to a comment.
const DATA_DESCRIPTOR: &[u8] = b"B13BWz\0";

/// The information level asked for, which is what carries name, type and
/// comment.
const LEVEL: u16 = 1;

/// The reply parameter block: a status, a converter, an entry count and an
/// available count.
const PARAMETERS_LEN: usize = 8;

/// A level 1 entry: 13 bytes of name, a pad byte, a 16-bit type and a 32-bit
/// pointer to the comment.
const ENTRY_LEN: usize = 20;
const NAME_LEN: usize = 13;

/// `NERR_Success`.
const SUCCESS: u16 = 0;

/// `ERROR_MORE_DATA` — the share list did not fit the reply.
///
/// The port does not retry with a larger receive buffer: the transaction
/// ceiling may not permit one, and the machinery for a RAP that cannot deliver
/// already exists. It is treated as RAP being unable to produce the list, and
/// enumeration falls through to `srvsvc` exactly as `STATUS_NOT_SUPPORTED`
/// does. The reference library treats it as fatal and enumerates nothing.
pub const ERROR_MORE_DATA: u16 = 234;

/// What a RAP reply can be that stops it decoding.
///
/// Every one of these ends RAP rather than ending share enumeration: the caller
/// falls through to `srvsvc`, which answers the same question in a format with
/// none of RAP's ambiguities.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RapError {
    /// The reply's parameter block was shorter than the four words every RAP
    /// reply opens with.
    #[error("RAP reply carries {0} parameter bytes, fewer than the 8 every reply opens with")]
    ParametersTooShort(usize),

    /// The share list did not fit the reply.
    ///
    /// Named apart from [`RapError::Failed`] because it is the one RAP failure
    /// that says nothing is wrong: the server had the list and could not send
    /// it. The port does not retry with a larger receive buffer and falls
    /// through to `srvsvc` instead, which is what the reference library does
    /// not do — it treats this as fatal and enumerates nothing.
    #[error("RAP NetShareEnum: the share list did not fit the reply")]
    MoreData,

    /// The call failed, and this is the code it failed with.
    #[error("RAP NetShareEnum failed: {0}")]
    Failed(u16),

    /// The entry the walk reached is not wholly inside the reply's data block.
    #[error("RAP entry {index} needs {needed} bytes of a {length}-byte data block")]
    TruncatedEntry {
        /// Which entry.
        index: u16,
        /// Where the entry ended.
        needed: usize,
        /// What the data block holds.
        length: usize,
    },

    /// A comment pointer that does not land inside the reply's data block, or
    /// lands on a string with no terminator.
    #[error("RAP entry {index} points its comment at offset {offset} of a {length}-byte block")]
    CommentOutOfRange {
        /// Which entry.
        index: u16,
        /// Where the converted pointer landed.
        offset: usize,
        /// What the data block holds.
        length: usize,
    },

    /// A name or comment that is not valid UTF-8.
    ///
    /// RAP strings are 8-bit in a code page the protocol never names, so a
    /// string outside ASCII cannot be decoded to text with any confidence.
    /// Refusing it falls through to `srvsvc`, whose strings are UTF-16 and
    /// carry no such ambiguity — which is a better answer than a share name
    /// decoded to the wrong characters.
    #[error("RAP entry {index} carries a {field} that is not valid UTF-8")]
    NotUtf8 {
        /// Which entry.
        index: u16,
        /// Which of its two strings.
        field: &'static str,
    },

    /// The reply succeeded while saying it had more entries than it returned.
    ///
    /// A server with more to send says so with [`ERROR_MORE_DATA`]. Saying it
    /// under a success status is a short list presented as a whole one, which
    /// is the silent truncation the crate refuses everywhere else.
    #[error("RAP reply returns {returned} of {available} entries under a success status")]
    ShortOfAvailable {
        /// `EntryCount`.
        returned: u16,
        /// `Available`.
        available: u16,
    },
}

/// The transaction parameter block of a `NetShareEnum` request.
///
/// `receive_buffer` is how large a reply data block the server may build, and
/// it is set from the transaction's own `MaxDataCount` rather than from
/// `0xFFFF`. The two have to agree: a server that built a larger reply than the
/// transaction allowed it to return would have that reply refused by the
/// connection layer as more than the request asked for, which reads as a
/// protocol error rather than as the size mistake it is. The reference sends
/// `0xFFFF` beside a `MaxDataCount` of 65,535 and so never meets it.
pub fn request(receive_buffer: u16) -> Vec<u8> {
    let mut parameters = Vec::with_capacity(19);
    parameters.extend_from_slice(&FUNCTION.to_le_bytes());
    parameters.extend_from_slice(PARAMETER_DESCRIPTOR);
    parameters.extend_from_slice(DATA_DESCRIPTOR);
    parameters.extend_from_slice(&LEVEL.to_le_bytes());
    parameters.extend_from_slice(&receive_buffer.to_le_bytes());
    parameters
}

/// Decodes a `NetShareEnum` reply from the transaction's parameter and data
/// blocks.
pub fn response(parameters: &[u8], data: &[u8]) -> Result<Vec<Share>, RapError> {
    let words: &[u8; PARAMETERS_LEN] = parameters
        .get(..PARAMETERS_LEN)
        .and_then(|raw| raw.try_into().ok())
        .ok_or(RapError::ParametersTooShort(parameters.len()))?;
    let word = |at: usize| u16::from_le_bytes([words[at], words[at + 1]]);

    match word(0) {
        SUCCESS => {}
        ERROR_MORE_DATA => return Err(RapError::MoreData),
        status => return Err(RapError::Failed(status)),
    }
    let converter = word(2);
    let returned = word(4);
    let available = word(6);
    if returned < available {
        return Err(RapError::ShortOfAvailable {
            returned,
            available,
        });
    }

    let mut shares = Vec::with_capacity(usize::from(returned).min(data.len() / ENTRY_LEN));
    for index in 0..returned {
        let at = usize::from(index) * ENTRY_LEN;
        let entry: &[u8; ENTRY_LEN] = data
            .get(at..at + ENTRY_LEN)
            .and_then(|raw| raw.try_into().ok())
            .ok_or(RapError::TruncatedEntry {
                index,
                needed: at + ENTRY_LEN,
                length: data.len(),
            })?;

        let name = nul_padded(&entry[..NAME_LEN]);
        let kind = ShareKind::from_rap(u16::from_le_bytes([entry[14], entry[15]]));
        let pointer = u32::from_le_bytes([entry[16], entry[17], entry[18], entry[19]]);

        // [MS-RAP] transmits a pointer as a 32-bit value whose low half, less
        // the reply's own converter word, is an offset into the data block. The
        // high half is the server's and means nothing here. The one answered
        // RAP reply in the corpus carries a converter of zero and a pointer of
        // 0x28, so it pins the arithmetic only where the two rules agree.
        let comment = if pointer == 0 {
            String::new()
        } else {
            let offset = usize::from((pointer as u16).wrapping_sub(converter));
            let tail = data.get(offset..).ok_or(RapError::CommentOutOfRange {
                index,
                offset,
                length: data.len(),
            })?;
            let end =
                tail.iter()
                    .position(|&byte| byte == 0)
                    .ok_or(RapError::CommentOutOfRange {
                        index,
                        offset,
                        length: data.len(),
                    })?;
            text(&tail[..end], index, "comment")?
        };

        shares.push(Share {
            name: text(name, index, "name")?,
            kind,
            comment,
        });
    }
    Ok(shares)
}

/// The bytes of a fixed-width field up to its first null.
fn nul_padded(field: &[u8]) -> &[u8] {
    let end = field
        .iter()
        .position(|&byte| byte == 0)
        .unwrap_or(field.len());
    &field[..end]
}

fn text(bytes: &[u8], index: u16, field: &'static str) -> Result<String, RapError> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|_| RapError::NotUtf8 { index, field })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::ShareService;
    use crate::wire::transaction::TransactionResponse;

    /// The one answered RAP reply in the corpus: the Samba container, asked by
    /// a harness corrected for the transaction `Name`.
    ///
    /// It is the only thing that can pin a RAP decoder's converted-pointer
    /// arithmetic offline — `Converter = 0`, a comment pointer of `0x28`, and a
    /// second entry whose comment is 26 characters at offset 41.
    #[test]
    fn the_answered_rap_reply_decodes_to_its_two_shares() {
        let message = crate::rpc::tests::fixture("capture-rap/0010-s2c-cmd25.bin");
        let reply = TransactionResponse::decode(&message).unwrap();
        assert_eq!(reply.total_parameter_count, 8);
        assert_eq!(reply.total_data_count, 68);
        // Status 0, Converter 0x0000, EntryCount 2, Available 2.
        assert_eq!(reply.parameters, [0, 0, 0, 0, 2, 0, 2, 0]);

        let shares = response(&reply.parameters, &reply.data).unwrap();
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].name, "testshare");
        assert_eq!(shares[0].kind.service, ShareService::Disk);
        assert!(!shares[0].kind.special);
        assert_eq!(shares[0].comment, "");
        assert_eq!(shares[1].name, "IPC$");
        assert_eq!(shares[1].kind.service, ShareService::Ipc);
        assert!(!shares[1].kind.special);
        assert_eq!(shares[1].comment, "IPC Service (Samba 4.23.8)");
    }

    /// The request parameter block, against the one Windows parsed rather than
    /// refused.
    ///
    /// The two differ in the receive buffer alone: the captured request asks
    /// for `0xFFFF` beside a `MaxDataCount` of 65,472, which is a server told
    /// it may build a larger reply than it is allowed to return. This crate
    /// sends the same number in both.
    #[test]
    fn the_request_matches_the_captured_one_but_for_its_receive_buffer() {
        let ours = request(crate::wire::transaction::MAX_DATA_COUNT);
        let message = crate::rpc::tests::fixture("capture-win-rap/0009-c2s-cmd25.bin");
        let theirs = crate::wire::transaction::TransactionRequest::decode(&message)
            .unwrap()
            .parameters;
        assert_eq!(ours.len(), theirs.len());
        assert_eq!(ours[..17], theirs[..17]);
        assert_eq!(&theirs[15..], &[1, 0, 0xFF, 0xFF]);
        assert_eq!(&ours[15..], &[1, 0, 0xC0, 0xFF]);
    }

    /// RAP's `ERROR_MORE_DATA` is a failure of RAP and so a fall-through, not a
    /// share list. The reference library treats it as fatal and enumerates
    /// nothing.
    #[test]
    fn more_data_fails_rap_rather_than_returning_a_short_list() {
        let mut parameters = Vec::new();
        parameters.extend_from_slice(&ERROR_MORE_DATA.to_le_bytes());
        parameters.extend_from_slice(&0u16.to_le_bytes());
        parameters.extend_from_slice(&1u16.to_le_bytes());
        parameters.extend_from_slice(&9u16.to_le_bytes());
        let mut data = vec![0; ENTRY_LEN];
        data[..4].copy_from_slice(b"only");
        assert_eq!(response(&parameters, &data), Err(RapError::MoreData));
    }

    /// A success that returns fewer entries than it says are available is the
    /// silent-truncation shape, and it is refused rather than handed back.
    #[test]
    fn a_success_short_of_its_own_available_count_is_refused() {
        let mut parameters = Vec::new();
        parameters.extend_from_slice(&SUCCESS.to_le_bytes());
        parameters.extend_from_slice(&0u16.to_le_bytes());
        parameters.extend_from_slice(&1u16.to_le_bytes());
        parameters.extend_from_slice(&4u16.to_le_bytes());
        let data = vec![0; ENTRY_LEN];
        assert_eq!(
            response(&parameters, &data),
            Err(RapError::ShortOfAvailable {
                returned: 1,
                available: 4
            })
        );
    }

    /// The converter is subtracted from the pointer's low half, which is the
    /// arithmetic [MS-RAP] specifies and which the corpus cannot distinguish
    /// from the reference's whole-word subtraction: its one reply carries a
    /// converter of zero.
    #[test]
    fn the_converter_is_subtracted_from_the_pointers_low_half() {
        let converter = 0x0100u16;
        let mut parameters = Vec::new();
        parameters.extend_from_slice(&SUCCESS.to_le_bytes());
        parameters.extend_from_slice(&converter.to_le_bytes());
        parameters.extend_from_slice(&1u16.to_le_bytes());
        parameters.extend_from_slice(&1u16.to_le_bytes());

        let mut data = vec![0; ENTRY_LEN];
        data[..5].copy_from_slice(b"share");
        data[14..16].copy_from_slice(&3u16.to_le_bytes());
        // A pointer whose high half is a server's own and whose low half, less
        // the converter, is the offset 20 the comment sits at.
        data[16..20].copy_from_slice(&0xABCD_0114u32.to_le_bytes());
        data.extend_from_slice(b"a remark\0");

        let shares = response(&parameters, &data).unwrap();
        assert_eq!(shares[0].name, "share");
        assert_eq!(shares[0].comment, "a remark");
        assert_eq!(shares[0].kind.service, ShareService::Ipc);
    }

    #[test]
    fn a_comment_pointer_outside_the_data_block_is_refused() {
        let mut parameters = Vec::new();
        parameters.extend_from_slice(&SUCCESS.to_le_bytes());
        parameters.extend_from_slice(&0u16.to_le_bytes());
        parameters.extend_from_slice(&1u16.to_le_bytes());
        parameters.extend_from_slice(&1u16.to_le_bytes());
        let mut data = vec![0; ENTRY_LEN];
        data[16..20].copy_from_slice(&9999u32.to_le_bytes());
        assert!(matches!(
            response(&parameters, &data),
            Err(RapError::CommentOutOfRange { .. })
        ));
    }

    #[test]
    fn an_entry_the_data_block_cannot_hold_is_refused() {
        let mut parameters = Vec::new();
        parameters.extend_from_slice(&SUCCESS.to_le_bytes());
        parameters.extend_from_slice(&0u16.to_le_bytes());
        parameters.extend_from_slice(&2u16.to_le_bytes());
        parameters.extend_from_slice(&2u16.to_le_bytes());
        let data = vec![0; ENTRY_LEN + 4];
        assert!(matches!(
            response(&parameters, &data),
            Err(RapError::TruncatedEntry { index: 1, .. })
        ));
    }
}
