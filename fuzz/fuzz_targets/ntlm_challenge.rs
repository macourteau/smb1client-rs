//! The NTLM challenge parser, which consumes server-supplied AV pairs before
//! authentication has completed.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = smb1client::fuzz::ntlm_challenge(data);
});
