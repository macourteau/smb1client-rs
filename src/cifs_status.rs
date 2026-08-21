//! The statuses [MS-CIFS] defines that [MS-ERREF] does not.
//!
//! [MS-ERREF] defines the NTSTATUS space and nothing beyond it, so the
//! generator behind [`status`](crate::status) hard-fails rather than invent a
//! name that specification does not define. `STATUS_INVALID_SMB` is one it
//! correctly refuses, and a status the generator refuses is a status to look
//! for in [MS-CIFS] rather than one to invent.
//!
//! [MS-CIFS] section 2.2.2.4 carries these beside the SMBSTATUS class/code
//! pairs they translate: the high half of each value is the SMB error code and
//! the low half is the error class, `0x0001` for ERRDOS and `0x0002` for
//! ERRSRV. They are hand-written here, each with its own citation, and the
//! generated table is left alone — the crate's status vocabulary is two
//! specifications rather than one specification with hand-patched holes in it.
//!
//! **The two value spaces overlap.** [MS-ERREF] defines `DBG_CONTINUE` at
//! `0x00010002`, which is [MS-CIFS]'s `STATUS_INVALID_SMB`, so
//! [`NtStatus::name`] — which answers from the generated table alone — reports
//! the debugger status for a value an SMB server can only have meant the other
//! way. [`Named`] is the display that prefers the [MS-CIFS] name for the
//! statuses named here, and it is what the error type formats a status with.
//!
//! [MS-CIFS]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-cifs/8f11e0f3-d545-46cc-97e6-f00569e3e1bc
//! [MS-ERREF]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55

use std::fmt;

use crate::status::NtStatus;

/// The statuses [MS-CIFS] section 2.2.2.4 defines and [MS-ERREF] does not.
///
/// They sit on [`NtStatus`] beside the generated table's own named constants so
/// that a status reads the same way wherever it is matched, and they are
/// written here rather than there because that file is generated.
impl NtStatus {
    /// `STATUS_SMB_BAD_FID` — the FID in the request names no open file.
    /// ERRDOS/ERRbadfid.
    pub const SMB_BAD_FID: Self = Self::new(0x0006_0001);

    /// `STATUS_OS2_INVALID_ACCESS` — the open mode in the request is invalid.
    /// ERRDOS/ERRbadaccess.
    pub const OS2_INVALID_ACCESS: Self = Self::new(0x000C_0001);

    /// `STATUS_OS2_NO_MORE_SIDS` — the server has no search handle left to open
    /// a search with. ERRDOS/ERROR_NO_MORE_SEARCH_HANDLES.
    pub const OS2_NO_MORE_SIDS: Self = Self::new(0x0071_0001);

    /// `STATUS_OS2_INVALID_LEVEL` — the information level the request asked for
    /// is one the server does not recognise. ERRDOS/ERRunknownlevel.
    pub const OS2_INVALID_LEVEL: Self = Self::new(0x007C_0001);

    /// `STATUS_OS2_NEGATIVE_SEEK` — the request seeks to a negative absolute
    /// offset. ERRDOS/ERRinvalidseek.
    pub const OS2_NEGATIVE_SEEK: Self = Self::new(0x0083_0001);

    /// `STATUS_OS2_CANCEL_VIOLATION` — no lock request was outstanding for the
    /// region the request cancels. ERRDOS/ERROR_CANCEL_VIOLATION.
    pub const OS2_CANCEL_VIOLATION: Self = Self::new(0x00AD_0001);

    /// `STATUS_OS2_ATOMIC_LOCKS_NOT_SUPPORTED` — the file system cannot change
    /// a lock's type atomically. ERRDOS/ERROR_ATOMIC_LOCKS_NOT_SUPPORTED.
    pub const OS2_ATOMIC_LOCKS_NOT_SUPPORTED: Self = Self::new(0x00AE_0001);

    /// `STATUS_OS2_CANNOT_COPY` — the server's copy functions cannot serve the
    /// request. ERRDOS/ERROR_CANNOT_COPY.
    pub const OS2_CANNOT_COPY: Self = Self::new(0x010A_0001);

    /// `STATUS_OS2_EAS_DIDNT_FIT` — the extended attributes did not fit in the
    /// response. ERRDOS/ERROR_EAS_DIDNT_FIT.
    pub const OS2_EAS_DIDNT_FIT: Self = Self::new(0x0113_0001);

    /// `STATUS_OS2_EA_ACCESS_DENIED` — access to the extended attribute was
    /// denied. ERRDOS/ERROR_EA_ACCESS_DENIED.
    pub const OS2_EA_ACCESS_DENIED: Self = Self::new(0x03E2_0001);

    /// `STATUS_INVALID_SMB` — the server could not make sense of the message:
    /// an unspecified server error, and what a server answers a request whose
    /// header does not begin `\xffSMB` with. ERRSRV/ERRerror.
    ///
    /// [MS-ERREF] gives this same value the unrelated name `DBG_CONTINUE`, so
    /// [`NtStatus::name`] reports that one; see the module documentation.
    pub const INVALID_SMB: Self = Self::new(0x0001_0002);

    /// `STATUS_SMB_BAD_TID` — the TID in the request names no tree connection.
    /// ERRSRV/ERRinvtid.
    pub const SMB_BAD_TID: Self = Self::new(0x0005_0002);

    /// `STATUS_SMB_BAD_COMMAND` — the server does not recognise the command
    /// code in the request. ERRSRV/ERRbadcmd.
    pub const SMB_BAD_COMMAND: Self = Self::new(0x0016_0002);

    /// `STATUS_SMB_BAD_UID` — the UID in the request names no session on this
    /// server. ERRSRV/ERRbaduid.
    pub const SMB_BAD_UID: Self = Self::new(0x005B_0002);

    /// `STATUS_SMB_USE_MPX` — the server cannot serve raw-mode transfers for
    /// the moment and asks for MPX mode instead. ERRSRV/ERRusempx.
    pub const SMB_USE_MPX: Self = Self::new(0x00FA_0002);

    /// `STATUS_SMB_USE_STANDARD` — the server cannot serve raw or MPX transfers
    /// for the moment and asks for standard reads and writes instead.
    /// ERRSRV/ERRusestd.
    pub const SMB_USE_STANDARD: Self = Self::new(0x00FB_0002);

    /// `STATUS_SMB_CONTINUE_MPX` — continue in MPX mode. [MS-CIFS] reserves
    /// this for future use. ERRSRV/ERRcontmpx.
    pub const SMB_CONTINUE_MPX: Self = Self::new(0x00FC_0002);

    /// `STATUS_SMB_NO_SUPPORT` — the function the request asks for is one the
    /// server does not offer. ERRSRV/ERRnosupport.
    pub const SMB_NO_SUPPORT: Self = Self::new(0xFFFF_0002);
}

/// The statuses above and the names [MS-CIFS] gives them, ascending, which is
/// what [`name`] binary-searches.
static NAMES: [(u32, &str); 18] = [
    (0x0001_0002, "STATUS_INVALID_SMB"),
    (0x0005_0002, "STATUS_SMB_BAD_TID"),
    (0x0006_0001, "STATUS_SMB_BAD_FID"),
    (0x000C_0001, "STATUS_OS2_INVALID_ACCESS"),
    (0x0016_0002, "STATUS_SMB_BAD_COMMAND"),
    (0x005B_0002, "STATUS_SMB_BAD_UID"),
    (0x0071_0001, "STATUS_OS2_NO_MORE_SIDS"),
    (0x007C_0001, "STATUS_OS2_INVALID_LEVEL"),
    (0x0083_0001, "STATUS_OS2_NEGATIVE_SEEK"),
    (0x00AD_0001, "STATUS_OS2_CANCEL_VIOLATION"),
    (0x00AE_0001, "STATUS_OS2_ATOMIC_LOCKS_NOT_SUPPORTED"),
    (0x00FA_0002, "STATUS_SMB_USE_MPX"),
    (0x00FB_0002, "STATUS_SMB_USE_STANDARD"),
    (0x00FC_0002, "STATUS_SMB_CONTINUE_MPX"),
    (0x010A_0001, "STATUS_OS2_CANNOT_COPY"),
    (0x0113_0001, "STATUS_OS2_EAS_DIDNT_FIT"),
    (0x03E2_0001, "STATUS_OS2_EA_ACCESS_DENIED"),
    (0xFFFF_0002, "STATUS_SMB_NO_SUPPORT"),
];

/// The [MS-CIFS] name for a status, or `None` where that specification defines
/// none.
pub fn name(status: NtStatus) -> Option<&'static str> {
    NAMES
        .binary_search_by_key(&status.code(), |&(code, _)| code)
        .ok()
        .map(|index| NAMES[index].1)
}

/// A status displayed by the name that means something on an SMB connection.
///
/// [MS-CIFS]'s name wins where both specifications define the value, which is
/// what tells `STATUS_INVALID_SMB` from the `DBG_CONTINUE` the generated table
/// answers with. Everything else displays exactly as [`NtStatus`] does.
pub struct Named(pub NtStatus);

impl fmt::Display for Named {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match name(self.0) {
            Some(name) => write!(f, "{name} (0x{:08X})", self.0.code()),
            None => write!(f, "{}", self.0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_name_is_sorted_and_matches_its_constant() {
        assert!(NAMES.windows(2).all(|pair| pair[0].0 < pair[1].0));
        assert_eq!(name(NtStatus::INVALID_SMB), Some("STATUS_INVALID_SMB"));
        assert_eq!(
            name(NtStatus::SMB_NO_SUPPORT),
            Some("STATUS_SMB_NO_SUPPORT")
        );
        assert_eq!(name(NtStatus::new(0xC000_0022)), None);
    }

    /// The generated table names `0x00010002` `DBG_CONTINUE`, which is a
    /// debugger status and not what a server answering an SMB request means by
    /// it. The specifications overlap here and the display resolves it.
    #[test]
    fn the_cifs_name_wins_where_the_two_specifications_collide() {
        assert_eq!(NtStatus::INVALID_SMB.name(), Some("DBG_CONTINUE"));
        assert_eq!(
            Named(NtStatus::INVALID_SMB).to_string(),
            "STATUS_INVALID_SMB (0x00010002)"
        );
    }

    #[test]
    fn a_status_cifs_does_not_name_displays_as_it_always_does() {
        let status = NtStatus::SHARING_VIOLATION;
        assert_eq!(Named(status).to_string(), status.to_string());
    }
}
