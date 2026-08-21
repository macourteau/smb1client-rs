//! The 32-byte SMB1 message header, and the command and flag values it carries.

use binrw::binrw;

use crate::status::NtStatus;

/// The length of the SMB1 header. Absolute offsets inside a message are
/// measured from its first byte.
pub const HEADER_LEN: usize = 32;

/// The header that opens every SMB1 message.
///
/// A plain `binrw` derive round-trips this byte-identically against captured
/// bytes, which is the property that makes a parsing crate worth taking over
/// hand-rolled byte pushing.
#[binrw]
#[brw(little, magic = b"\xffSMB")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SmbHeader {
    /// The command this message carries.
    pub command: u8,
    /// The NT status, present because `SMB_FLAGS2_NT_STATUS` is negotiated.
    #[br(map = NtStatus::new)]
    #[bw(map = |status: &NtStatus| status.code())]
    pub status: NtStatus,
    /// See [`FLAGS_CLIENT`].
    pub flags: u8,
    /// See [`FLAGS2_CLIENT`].
    pub flags2: u16,
    /// The high 16 bits of the process id.
    pub pid_high: u16,
    /// The signature field. This crate does not sign, so it sends zeroes.
    pub security_features: [u8; 8],
    /// Reserved.
    pub reserved: u16,
    /// Tree id.
    pub tid: u16,
    /// The low 16 bits of the process id.
    pub pid_low: u16,
    /// User id, assigned by the session setup.
    pub uid: u16,
    /// Multiplex id. Responses return out of order and this is what routes them.
    pub mid: u16,
}

impl SmbHeader {
    /// A request header carrying this crate's flag words.
    pub fn request(command: u8) -> Self {
        Self {
            command,
            status: NtStatus::SUCCESS,
            flags: FLAGS_CLIENT,
            flags2: FLAGS2_CLIENT,
            pid_high: 0,
            security_features: [0; 8],
            reserved: 0,
            tid: 0,
            pid_low: 1,
            uid: 0,
            mid: 0,
        }
    }
}

/// `SMB_FLAGS_CASE_INSENSITIVE`.
pub const FLAGS_CASE_INSENSITIVE: u8 = 0x08;
/// `SMB_FLAGS_CANONICALIZED_PATHS`.
pub const FLAGS_CANONICALIZED_PATHS: u8 = 0x10;
/// The `Flags` byte this crate sends.
pub const FLAGS_CLIENT: u8 = FLAGS_CASE_INSENSITIVE | FLAGS_CANONICALIZED_PATHS;

/// `SMB_FLAGS2_KNOWS_LONG_NAMES`.
pub const FLAGS2_KNOWS_LONG_NAMES: u16 = 0x0001;
/// `SMB_FLAGS2_KNOWS_EAS`. Deliberately **not** sent: it claims the client
/// understands extended attributes, and this crate implements none.
pub const FLAGS2_KNOWS_EAS: u16 = 0x0002;
/// `SMB_FLAGS2_IS_LONG_NAME`. A different bit from [`FLAGS2_KNOWS_LONG_NAMES`],
/// and not sent either.
pub const FLAGS2_IS_LONG_NAME: u16 = 0x0040;
/// `SMB_FLAGS2_EXTENDED_SECURITY`. The request-side half of the
/// `CAP_EXTENDED_SECURITY` floor: it is what says the `SESSION_SETUP_ANDX` this
/// crate sends carries a SPNEGO blob rather than the pre-extended-security
/// fields.
pub const FLAGS2_EXTENDED_SECURITY: u16 = 0x0800;
/// `SMB_FLAGS2_NT_STATUS`.
pub const FLAGS2_NT_STATUS: u16 = 0x4000;
/// `SMB_FLAGS2_UNICODE`.
pub const FLAGS2_UNICODE: u16 = 0x8000;

/// The `Flags2` word this crate sends: the four bits it relies on and no
/// others.
///
/// The reference library sends `0xC803`, which is this plus
/// [`FLAGS2_KNOWS_EAS`]. That bit is a false claim and is dropped; the drop has
/// reached no server, so it sits on the conformance script.
pub const FLAGS2_CLIENT: u16 =
    FLAGS2_UNICODE | FLAGS2_NT_STATUS | FLAGS2_EXTENDED_SECURITY | FLAGS2_KNOWS_LONG_NAMES;

/// SMB1 command codes.
pub mod command {
    /// `SMB_COM_CLOSE`.
    pub const CLOSE: u8 = 0x04;
    /// `SMB_COM_RENAME`.
    pub const RENAME: u8 = 0x07;
    /// `SMB_COM_TRANSACTION`.
    pub const TRANSACTION: u8 = 0x25;
    /// `SMB_COM_READ_ANDX`.
    pub const READ_ANDX: u8 = 0x2E;
    /// `SMB_COM_WRITE_ANDX`.
    pub const WRITE_ANDX: u8 = 0x2F;
    /// `SMB_COM_TRANSACTION2`.
    pub const TRANSACTION2: u8 = 0x32;
    /// `SMB_COM_FIND_CLOSE2`.
    pub const FIND_CLOSE2: u8 = 0x34;
    /// `SMB_COM_TREE_DISCONNECT`.
    pub const TREE_DISCONNECT: u8 = 0x71;
    /// `SMB_COM_NEGOTIATE`.
    pub const NEGOTIATE: u8 = 0x72;
    /// `SMB_COM_SESSION_SETUP_ANDX`.
    pub const SESSION_SETUP_ANDX: u8 = 0x73;
    /// `SMB_COM_LOGOFF_ANDX`.
    pub const LOGOFF_ANDX: u8 = 0x74;
    /// `SMB_COM_TREE_CONNECT_ANDX`.
    pub const TREE_CONNECT_ANDX: u8 = 0x75;
    /// `SMB_COM_ECHO`.
    pub const ECHO: u8 = 0x2B;
    /// `SMB_COM_NT_CREATE_ANDX`.
    pub const NT_CREATE_ANDX: u8 = 0xA2;
}
