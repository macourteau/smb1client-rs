//! The status classification read the way a caller reads it, through the
//! public surface.
//!
//! Every status here is written as the raw code the specification gives it,
//! rather than through the constant the crate names it with, so a constant
//! bound to the wrong code fails these rather than agreeing with itself.

use std::io::{self, ErrorKind};

use smb1client::{Error, NtStatus, cifs_status};

/// The four spellings of "file does not exist". Which one a server answers with
/// depends on the server rather than on what went wrong, so a caller matching
/// one of them alone has a bug that appears against one server family only.
const NOT_FOUND: &[(u32, &str)] = &[
    (0xC000_000F, "STATUS_NO_SUCH_FILE"),
    (0xC000_0034, "STATUS_OBJECT_NAME_NOT_FOUND"),
    (0xC000_003A, "STATUS_OBJECT_PATH_NOT_FOUND"),
    (0xC000_0225, "STATUS_NOT_FOUND"),
];

/// The statuses a server answers a failed logon with, and the two further
/// permission failures beside them.
const PERMISSION_DENIED: &[(u32, &str)] = &[
    (0xC000_0022, "STATUS_ACCESS_DENIED"),
    (0xC000_0061, "STATUS_PRIVILEGE_NOT_HELD"),
    (0xC000_0062, "STATUS_INVALID_ACCOUNT_NAME"),
    (0xC000_0064, "STATUS_NO_SUCH_USER"),
    (0xC000_006A, "STATUS_WRONG_PASSWORD"),
    (0xC000_006D, "STATUS_LOGON_FAILURE"),
    (0xC000_006E, "STATUS_ACCOUNT_RESTRICTION"),
    (0xC000_006F, "STATUS_INVALID_LOGON_HOURS"),
    (0xC000_0070, "STATUS_INVALID_WORKSTATION"),
    (0xC000_0071, "STATUS_PASSWORD_EXPIRED"),
    (0xC000_0072, "STATUS_ACCOUNT_DISABLED"),
    (0xC000_00CA, "STATUS_NETWORK_ACCESS_DENIED"),
    (0xC000_010B, "STATUS_INVALID_LOGON_TYPE"),
    (0xC000_0155, "STATUS_LOGON_NOT_GRANTED"),
    (0xC000_015B, "STATUS_LOGON_TYPE_NOT_GRANTED"),
    (0xC000_0193, "STATUS_ACCOUNT_EXPIRED"),
    (0xC000_0224, "STATUS_PASSWORD_MUST_CHANGE"),
    (0xC000_0250, "STATUS_INSUFFICIENT_LOGON_INFO"),
    (0xC000_02FA, "STATUS_SMARTCARD_LOGON_REQUIRED"),
];

/// The conditions that pass on their own, which is what a caller keys a retry
/// on.
const RESOURCE_BUSY: &[(u32, &str)] = &[
    (0x0000_0103, "STATUS_PENDING"),
    (0xC000_0043, "STATUS_SHARING_VIOLATION"),
    (0xC000_00A3, "STATUS_DEVICE_NOT_READY"),
    (0xC000_00BF, "STATUS_NETWORK_BUSY"),
    (0xC000_00CE, "STATUS_TOO_MANY_SESSIONS"),
    (0xC000_022D, "STATUS_RETRY"),
];

/// Statuses this crate consumes rather than reports: the pipe read loop reads
/// through a buffer overflow, the file read loop reads end-of-file as the end
/// of the span, and a listing ends normally on no-more-files. None of them
/// reaches a caller as an error, so none of them is classified — and a mapping
/// added for one later would be a sign the loop that owns it stopped consuming
/// it.
const UNCLASSIFIED_BY_DESIGN: &[(u32, &str)] = &[
    (0x8000_0005, "STATUS_BUFFER_OVERFLOW"),
    (0x8000_0006, "STATUS_NO_MORE_FILES"),
    (0xC000_0011, "STATUS_END_OF_FILE"),
];

fn kind_of(code: u32) -> ErrorKind {
    Error::Status(NtStatus::new(code)).kind()
}

#[test]
fn every_spelling_of_not_found_reaches_not_found() {
    for &(code, name) in NOT_FOUND {
        assert_eq!(kind_of(code), ErrorKind::NotFound, "{name}");
    }
}

#[test]
fn the_filesystem_verbs_statuses_reach_the_kinds_the_verbs_turn_on() {
    assert_eq!(kind_of(0xC000_0101), ErrorKind::DirectoryNotEmpty);
    assert_eq!(kind_of(0xC000_0103), ErrorKind::NotADirectory);
    assert_eq!(kind_of(0xC000_00BA), ErrorKind::IsADirectory);
    assert_eq!(kind_of(0xC000_0008), ErrorKind::InvalidInput);
    // What `rename` answers with when the destination exists. It does not
    // overwrite one, which is where this differs from `std::fs::rename`.
    assert_eq!(kind_of(0xC000_0035), ErrorKind::AlreadyExists);
    assert_eq!(kind_of(0x4000_0000), ErrorKind::AlreadyExists);
}

/// A sharing violation is a transient conflict with another open handle, not an
/// authorization failure. The reference library groups it with the permission
/// failures and this crate overrules that deliberately, because a caller that
/// retries on busy and gives up on denied needs the two apart.
#[test]
fn a_sharing_violation_is_busy_and_not_denied() {
    assert_eq!(kind_of(0xC000_0043), ErrorKind::ResourceBusy);
    assert_ne!(kind_of(0xC000_0043), ErrorKind::PermissionDenied);
}

#[test]
fn the_authentication_and_permission_statuses_reach_permission_denied() {
    for &(code, name) in PERMISSION_DENIED {
        assert_eq!(kind_of(code), ErrorKind::PermissionDenied, "{name}");
    }
}

#[test]
fn the_temporary_statuses_reach_resource_busy() {
    for &(code, name) in RESOURCE_BUSY {
        assert_eq!(kind_of(code), ErrorKind::ResourceBusy, "{name}");
    }
}

/// The table has 1,796 entries and the classification covers a few dozen, so
/// this is the branch most failures take. What keeps it from being lossy is
/// that the status survives it.
#[test]
fn an_unclassified_status_reaches_other_with_its_status_intact() {
    // Defined by the specification, classified by nothing here.
    let defined = Error::Status(NtStatus::new(0xC000_007F));
    assert_eq!(defined.kind(), ErrorKind::Other);
    assert_eq!(defined.status().map(NtStatus::code), Some(0xC000_007F));
    assert_eq!(
        defined.status().and_then(NtStatus::name),
        Some("STATUS_DISK_FULL")
    );

    // Defined by nothing at all, which a server is free to send anyway.
    let unknown = Error::Status(NtStatus::new(0xC0FF_EE00));
    assert_eq!(unknown.kind(), ErrorKind::Other);
    assert_eq!(unknown.status().map(NtStatus::code), Some(0xC0FF_EE00));
    assert_eq!(unknown.status().and_then(NtStatus::name), None);

    for &(code, name) in UNCLASSIFIED_BY_DESIGN {
        assert_eq!(kind_of(code), ErrorKind::Other, "{name}");
    }
}

#[test]
fn the_named_status_errors_hand_back_the_status_they_stand_for() {
    assert_eq!(
        Error::TransactionRefused.status().map(NtStatus::code),
        Some(0xC000_0205),
    );
    assert_eq!(Error::TransactionRefused.kind(), ErrorKind::Other);

    assert_eq!(
        Error::TreeDisconnected.status().map(NtStatus::code),
        Some(0xC000_00C9),
    );
    assert_eq!(Error::TreeDisconnected.kind(), ErrorKind::NotConnected);

    let lost = Error::ConnectionLost {
        status: Some(NtStatus::USER_SESSION_DELETED),
    };
    assert_eq!(lost.status().map(NtStatus::code), Some(0xC000_0203));
    assert_eq!(lost.kind(), ErrorKind::ConnectionAborted);
}

/// A failure that never came from the server carries no status to hand back,
/// and saying so is what keeps `status()` honest.
#[test]
fn a_failure_that_carried_no_status_says_so() {
    let transport = Error::Io(io::Error::new(ErrorKind::BrokenPipe, "socket closed"));
    assert_eq!(transport.status(), None);
    assert_eq!(transport.kind(), ErrorKind::BrokenPipe);

    let decode = Error::Protocol("byte count runs past the message".into());
    assert_eq!(decode.status(), None);
    assert_eq!(decode.kind(), ErrorKind::InvalidData);

    assert_eq!(Error::RequestTimeout.status(), None);
    assert_eq!(Error::RequestTimeout.kind(), ErrorKind::TimedOut);
    assert_eq!(Error::ConnectTimeout.kind(), ErrorKind::TimedOut);
    assert_eq!(Error::ConnectionLost { status: None }.status(), None);
}

/// The conversion is what lets a consumer's `io::Result` functions use `?` on
/// this crate without a hand-written arm, and it is worth nothing if the kind
/// does not survive it.
#[test]
fn converting_into_an_io_error_preserves_the_kind() {
    let cases: Vec<Error> = vec![
        Error::Status(NtStatus::new(0xC000_0034)),
        Error::Status(NtStatus::new(0xC000_0043)),
        Error::Status(NtStatus::new(0xC0FF_EE00)),
        Error::TransactionTooLarge {
            request: "TRANS2_FIND_FIRST2",
            size: 70_000,
            limit: 66_524,
        },
        Error::ConnectionLost { status: None },
        Error::TreeDisconnected,
        Error::GuestLogon,
        Error::SigningRequired,
        Error::InvalidPath("..\\..\\etc\\passwd escapes the share root".into()),
    ];

    for error in cases {
        let expected = error.kind();
        let message = error.to_string();
        let converted = io::Error::from(error);
        assert_eq!(converted.kind(), expected);
        // The error itself survives as the source, so nothing of what it said
        // is lost in the conversion.
        assert_eq!(converted.get_ref().unwrap().to_string(), message);
    }
}

/// A transport failure is already an `io::Error`, and the conversion hands the
/// same one back rather than burying it a layer deeper.
#[test]
fn converting_a_transport_failure_unwraps_it() {
    let converted = io::Error::from(Error::Io(io::Error::from_raw_os_error(32)));
    assert_eq!(converted.kind(), ErrorKind::BrokenPipe);
    assert_eq!(converted.raw_os_error(), Some(32));
}

/// [MS-ERREF] does not define `STATUS_INVALID_SMB`, and the generator refuses
/// to invent it, so it is hand-written from [MS-CIFS] section 2.2.2.4 instead.
/// [MS-ERREF] does define the same *value* as the unrelated `DBG_CONTINUE`,
/// which is why a status is displayed by the name that means something on an
/// SMB connection.
#[test]
fn the_ms_cifs_statuses_are_named_where_ms_erref_names_nothing() {
    assert_eq!(NtStatus::INVALID_SMB.code(), 0x0001_0002);
    assert_eq!(
        cifs_status::name(NtStatus::INVALID_SMB),
        Some("STATUS_INVALID_SMB")
    );
    assert_eq!(
        cifs_status::name(NtStatus::SMB_BAD_TID),
        Some("STATUS_SMB_BAD_TID")
    );
    assert_eq!(
        cifs_status::name(NtStatus::SMB_BAD_UID),
        Some("STATUS_SMB_BAD_UID")
    );
    assert_eq!(
        cifs_status::name(NtStatus::SHARING_VIOLATION),
        None,
        "a status [MS-ERREF] defines is not one [MS-CIFS] names"
    );

    let error = Error::Status(NtStatus::INVALID_SMB);
    assert!(
        error
            .to_string()
            .contains("STATUS_INVALID_SMB (0x00010002)"),
        "{error}"
    );
    assert_eq!(error.kind(), ErrorKind::Other);
    assert_eq!(error.status(), Some(NtStatus::INVALID_SMB));
}
