//! The SPNEGO decoder, which reads lenient BER — indefinite lengths and all —
//! out of a token an unauthenticated peer chose.
//!
//! Hand-rolling it is justified by its being a smaller attack surface than a
//! general ASN.1 crate, which is worth something only if the small surface is
//! treated as one.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = smb1client::fuzz::spnego(data);
});
