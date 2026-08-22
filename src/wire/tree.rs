//! `SMB_COM_TREE_CONNECT_ANDX` and `SMB_COM_TREE_DISCONNECT`.

use binrw::binrw;

use super::andx::AndX;
use super::header::command;
use super::offsets::{ByteArea, require_word_aligned};
use super::{Message, WireError, body, from_utf16, read_words, utf16z, write_words};

/// The `WordCount` of a tree-connect request.
const REQUEST_WORDS: u8 = 4;

/// The service string for a disk share.
pub const SERVICE_DISK: &str = "A:";

/// The service string for the inter-process-communication share.
pub const SERVICE_IPC: &str = "IPC";

/// The service string that lets the server choose.
pub const SERVICE_ANY: &str = "?????";

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct RequestWords {
    andx: AndX,
    flags: u16,
    password_length: u16,
}

#[binrw]
#[brw(little)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResponseWords {
    andx: AndX,
    optional_support: u16,
}

/// A tree-connect request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeConnectAndxRequest {
    /// Disconnect-the-old-tree and extended-response bits.
    pub flags: u16,
    /// The password bytes.
    ///
    /// Under extended security there is no password to send, and yet this is
    /// not empty: it holds one null byte, and `PasswordLength` declares it.
    /// That declared byte is what puts the path on an even offset — the byte
    /// area begins at 43, which is odd. Writing it as a pad while leaving
    /// `PasswordLength` at 0 mis-declares the field, and the server reads the
    /// path a byte early.
    pub password: Vec<u8>,
    /// The UNC path of the share.
    pub path: String,
    /// The service string, one of [`SERVICE_DISK`], [`SERVICE_IPC`] or
    /// [`SERVICE_ANY`]. It is ASCII whatever `SMB_FLAGS2_UNICODE` says.
    pub service: String,
}

impl TreeConnectAndxRequest {
    /// A tree connect to `path`, declaring the one-byte password that aligns it.
    pub fn new(path: &str, service: &str) -> Self {
        Self {
            flags: 0,
            password: vec![0],
            path: path.to_owned(),
            service: service.to_owned(),
        }
    }

    /// Encodes the command body.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        let mut area = ByteArea::for_word_count(usize::from(REQUEST_WORDS));
        area.put(&self.password);
        require_word_aligned("Path", area.offset())?;
        area.put(&utf16z(&self.path));
        area.put(self.service.as_bytes());
        area.put(&[0]);

        let words = RequestWords {
            andx: AndX::NONE,
            flags: self.flags,
            password_length: self.password.len() as u16,
        };
        Ok(body(&write_words(&words)?, &area.finish()))
    }

    /// Decodes a tree-connect request.
    pub fn decode(message: &Message) -> Result<Self, WireError> {
        message.expect_words(command::TREE_CONNECT_ANDX, &[REQUEST_WORDS], "4")?;
        let words: RequestWords = read_words(message.words())?;
        let area = message.byte_area()?;

        let password_length = usize::from(words.password_length);
        let (password, rest) =
            area.split_at_checked(password_length)
                .ok_or(WireError::Truncated {
                    part: "Password",
                    declared: password_length,
                    length: area.len(),
                })?;

        let path_end = find_utf16_terminator(rest)?;
        let path = from_utf16("Path", 0, &rest[..path_end])?;
        let service = ascii_z("Service", &rest[path_end + 2..])?;

        Ok(Self {
            flags: words.flags,
            password: password.to_vec(),
            path,
            service,
        })
    }
}

/// A tree-connect response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeConnectAndxResponse {
    /// The AndX prologue as it arrived.
    ///
    /// Every Windows tree-connect response in the corpus carries the SMB
    /// message length in its offset beside `AndXCommand = 0xFF`. Nothing
    /// consults the offset; it is kept because it is what the frame said.
    pub andx: AndX,
    /// Search bits and share-type bits the server supports.
    pub optional_support: u16,
    /// The service the server bound the tree to.
    pub service: String,
    /// The filesystem name, as Unicode.
    pub native_file_system: String,
}

impl TreeConnectAndxResponse {
    /// Decodes a tree-connect response.
    ///
    /// Three words is the ordinary shape and seven is the extended one, which
    /// adds two access masks this crate does not use.
    pub fn decode(message: &Message) -> Result<Self, WireError> {
        message.expect_words(command::TREE_CONNECT_ANDX, &[3, 7], "3 or 7")?;
        let words: ResponseWords = read_words(message.words())?;
        // `AndXOffset` beside the sentinel is read and ignored. Every Windows
        // tree-connect response in the corpus carries the SMB message length
        // there.
        words.andx.refuse_chaining()?;

        let area = message.byte_area()?;
        let service_end = area
            .iter()
            .position(|&byte| byte == 0)
            .ok_or(WireError::Truncated {
                part: "Service",
                declared: area.len(),
                length: area.len(),
            })?;
        let service = ascii_z("Service", area)?;

        // The filesystem name is Unicode and has to start on a word boundary,
        // which a server reaches by padding when the ASCII service before it
        // left an odd offset.
        let mut rest = &area[service_end + 1..];
        let name_at = message.byte_area_offset() + service_end + 1;
        if !name_at.is_multiple_of(2) && !rest.is_empty() {
            rest = &rest[1..];
        }
        let name_end = find_utf16_terminator(rest)?;

        Ok(Self {
            andx: words.andx,
            optional_support: words.optional_support,
            service,
            native_file_system: from_utf16("NativeFileSystem", 0, &rest[..name_end])?,
        })
    }

    /// Encodes the command body.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        let mut area = ByteArea::for_word_count(3);
        area.put(self.service.as_bytes());
        area.put(&[0]);
        area.align_to(2);
        area.put(&utf16z(&self.native_file_system));

        let words = ResponseWords {
            andx: self.andx,
            optional_support: self.optional_support,
        };
        Ok(body(&write_words(&words)?, &area.finish()))
    }
}

/// A tree disconnect. It carries no words and no bytes in either direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TreeDisconnect;

impl TreeDisconnect {
    /// Encodes the command body.
    pub fn encode_body(&self) -> Result<Vec<u8>, WireError> {
        Ok(body(&[], &[]))
    }

    /// Decodes a tree disconnect in either direction.
    ///
    /// Zero words here is the ordinary shape rather than the error shape, which
    /// is why the rule is stated per command rather than as a property of the
    /// status.
    pub fn decode(message: &Message) -> Result<Self, WireError> {
        message.expect_words(command::TREE_DISCONNECT, &[0], "0")?;
        Ok(Self)
    }
}

/// Finds the null terminator of a UTF-16LE string.
fn find_utf16_terminator(bytes: &[u8]) -> Result<usize, WireError> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .position(|pair| pair == &[0, 0])
        .map(|units| units * 2)
        .ok_or(WireError::Truncated {
            part: "UTF-16 string terminator",
            declared: bytes.len(),
            length: bytes.len(),
        })
}

/// Reads a null-terminated ASCII string.
fn ascii_z(field: &'static str, bytes: &[u8]) -> Result<String, WireError> {
    let end = bytes
        .iter()
        .position(|&byte| byte == 0)
        .ok_or(WireError::Truncated {
            part: field,
            declared: bytes.len(),
            length: bytes.len(),
        })?;
    Ok(String::from_utf8_lossy(&bytes[..end]).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The path lands on 44 because of the declared password byte at 43, not
    /// because of a pad.
    #[test]
    fn the_declared_password_byte_is_what_aligns_the_path() {
        let request = TreeConnectAndxRequest::new("\\\\127.0.0.1\\TESTSHARE", SERVICE_DISK);
        let encoded = request.encode_body().unwrap();
        let words: RequestWords = read_words(&encoded[1..1 + 8]).unwrap();
        assert_eq!(words.password_length, 1);
        assert_eq!(ByteArea::for_word_count(4).offset(), 43);
    }

    /// A password of even length would leave the path on 43, and the encoder
    /// refuses rather than shifting every character of it by a byte.
    #[test]
    fn an_unaligned_path_is_refused() {
        let mut request = TreeConnectAndxRequest::new("\\\\host\\share", SERVICE_DISK);
        request.password = Vec::new();
        assert!(matches!(
            request.encode_body(),
            Err(WireError::MisalignedName {
                field: "Path",
                offset: 43
            })
        ));
    }
}
