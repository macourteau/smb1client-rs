//! The negotiate-response parser, which runs before anything has
//! authenticated: it is the first server message the crate reads for content.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = smb1client::fuzz::negotiate_response(data);
});
