//! The frame decoder: a NetBIOS session-service header and the SMB message
//! inside it.
//!
//! It is the first thing a connection does with bytes off the socket, so
//! everything else in the crate is downstream of it.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = smb1client::fuzz::frame(data);
});
