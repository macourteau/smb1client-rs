//! The status table read the way a caller reads it, through the public surface.
//!
//! The expectations here are written by hand against [MS-ERREF] rather than
//! derived from the generator, so a generator that starts producing a plausible
//! but wrong table fails these.
//!
//! [MS-ERREF]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-erref/596a1078-e883-4972-9bbc-49e60bebca55

use smb1client::NtStatus;

/// Sampled across the four severity ranges the specification uses, so a table
/// truncated anywhere loses one of these.
const SAMPLE: &[(u32, &str)] = &[
    (0x0000_0000, "STATUS_SUCCESS"),
    (0x0000_0103, "STATUS_PENDING"),
    (0x0000_0367, "STATUS_WAIT_FOR_OPLOCK"),
    (0x4000_0000, "STATUS_OBJECT_NAME_EXISTS"),
    (0x8000_0005, "STATUS_BUFFER_OVERFLOW"),
    (0x8000_0006, "STATUS_NO_MORE_FILES"),
    (0xC000_0034, "STATUS_OBJECT_NAME_NOT_FOUND"),
    (0xC000_0043, "STATUS_SHARING_VIOLATION"),
    (0xC000_0205, "STATUS_INSUFF_SERVER_RESOURCES"),
    (0xC05D_0001, "STATUS_SMB_BAD_CLUSTER_DIALECT"),
];

/// Every status the design document turns on by name, paired with the name the
/// specification gives it.
const NAMED: &[(NtStatus, &str)] = &[
    (NtStatus::SUCCESS, "STATUS_SUCCESS"),
    (NtStatus::PENDING, "STATUS_PENDING"),
    (NtStatus::BUFFER_OVERFLOW, "STATUS_BUFFER_OVERFLOW"),
    (NtStatus::NO_MORE_FILES, "STATUS_NO_MORE_FILES"),
    (NtStatus::INVALID_HANDLE, "STATUS_INVALID_HANDLE"),
    (NtStatus::INVALID_PARAMETER, "STATUS_INVALID_PARAMETER"),
    (NtStatus::NO_SUCH_FILE, "STATUS_NO_SUCH_FILE"),
    (NtStatus::END_OF_FILE, "STATUS_END_OF_FILE"),
    (
        NtStatus::MORE_PROCESSING_REQUIRED,
        "STATUS_MORE_PROCESSING_REQUIRED",
    ),
    (
        NtStatus::OBJECT_NAME_NOT_FOUND,
        "STATUS_OBJECT_NAME_NOT_FOUND",
    ),
    (
        NtStatus::OBJECT_NAME_COLLISION,
        "STATUS_OBJECT_NAME_COLLISION",
    ),
    (
        NtStatus::OBJECT_PATH_NOT_FOUND,
        "STATUS_OBJECT_PATH_NOT_FOUND",
    ),
    (NtStatus::SHARING_VIOLATION, "STATUS_SHARING_VIOLATION"),
    (NtStatus::FILE_IS_A_DIRECTORY, "STATUS_FILE_IS_A_DIRECTORY"),
    (NtStatus::NOT_SUPPORTED, "STATUS_NOT_SUPPORTED"),
    (NtStatus::DUPLICATE_NAME, "STATUS_DUPLICATE_NAME"),
    (
        NtStatus::NETWORK_NAME_DELETED,
        "STATUS_NETWORK_NAME_DELETED",
    ),
    (NtStatus::DIRECTORY_NOT_EMPTY, "STATUS_DIRECTORY_NOT_EMPTY"),
    (NtStatus::NOT_A_DIRECTORY, "STATUS_NOT_A_DIRECTORY"),
    (
        NtStatus::USER_SESSION_DELETED,
        "STATUS_USER_SESSION_DELETED",
    ),
    (
        NtStatus::INSUFF_SERVER_RESOURCES,
        "STATUS_INSUFF_SERVER_RESOURCES",
    ),
    (NtStatus::NOT_FOUND, "STATUS_NOT_FOUND"),
];

/// A code in a range the specification leaves empty, and expected to stay that
/// way: the customer-defined bit is set, which Microsoft does not assign.
const UNRECOGNIZED: NtStatus = NtStatus::new(0xE123_4567);

#[test]
fn known_codes_resolve_to_their_specification_names() {
    for &(code, name) in SAMPLE {
        assert_eq!(NtStatus::new(code).name(), Some(name), "0x{code:08X}");
    }
}

#[test]
fn the_raw_code_survives_the_round_trip() {
    for &(code, _) in SAMPLE {
        assert_eq!(NtStatus::new(code).code(), code);
    }
    assert_eq!(UNRECOGNIZED.code(), 0xE123_4567);
}

#[test]
fn named_constants_carry_the_codes_the_specification_gives_them() {
    for &(status, name) in NAMED {
        assert_eq!(status.name(), Some(name), "0x{:08X}", status.code());
    }
}

#[test]
fn an_unrecognized_code_has_no_name_and_still_prints_its_hex() {
    assert_eq!(UNRECOGNIZED.name(), None);
    assert_eq!(
        UNRECOGNIZED.to_string(),
        "unrecognized NT status 0xE1234567"
    );
    assert_eq!(format!("{UNRECOGNIZED:?}"), "NtStatus(0xE1234567)");
}

#[test]
fn a_recognized_code_prints_its_name_and_its_hex() {
    let status = NtStatus::OBJECT_NAME_NOT_FOUND;
    assert_eq!(
        status.to_string(),
        "STATUS_OBJECT_NAME_NOT_FOUND (0xC0000034)"
    );
    assert_eq!(
        format!("{status:?}"),
        "NtStatus(0xC0000034 STATUS_OBJECT_NAME_NOT_FOUND)"
    );
}
