//! Stream a remote file through `tokio::io::copy`, without holding it in
//! memory.
//!
//! This is the case the adapters exist for. `Tree::read` allocates the whole
//! file and `read_exact_at` needs a span you already know the length of;
//! neither suits a file that is large, or whose size you cannot vouch for.
//! `File::into_reader` gives you an `AsyncRead`, and from there the file is an
//! ordinary tokio stream: `copy`, `BufReader`, `read_to_end`, anything that
//! takes `impl AsyncRead`.
//!
//! This example only reads. `File::into_writer` is the mirror image for the
//! other direction, and `write_file.rs` shows it.
//!
//! ```text
//! cargo run --example stream_file -- '\\127.0.0.1:10445\testshare' smbtest smbtest bigfile.bin
//! cargo run --example stream_file -- '\\host\share' user pass bigfile.bin ./local-copy.bin
//! ```

use std::process::ExitCode;

use tokio::io::AsyncWriteExt;

use smb1client::{Client, ClientConfig, Credentials, UncPath};

/// Prints the failure's `Display` and exits non-zero.
///
/// A `main` returning `Result` would print the error's `Debug` instead, which
/// for this crate's `Error` is the variant name and nothing else — `GuestLogon`
/// rather than the sentence explaining what the server did.
#[tokio::main]
async fn main() -> ExitCode {
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = std::env::args().skip(1);
    let (Some(unc), Some(user), Some(password), Some(remote)) = (
        arguments.next(),
        arguments.next(),
        arguments.next(),
        arguments.next(),
    ) else {
        return Err(
            "usage: stream_file <\\\\host[:port]\\share> <user> <password> <remote> [local]".into(),
        );
    };
    // No local destination means count the bytes and throw them away, which is
    // the safe thing to do to an unfamiliar file.
    let local = arguments.next();

    let unc: UncPath = unc.parse()?;
    let client = Client::new(ClientConfig {
        allow_guest: std::env::var_os("SMB1_ALLOW_GUEST").is_some(),
        ..ClientConfig::new(Credentials::new(user, password))
    });
    let tree = client.tree(&unc).await?;

    let file = tree.open(&remote).await?;
    // A hint for the progress line below, and nothing more. Do not size a
    // buffer against it and do not stop reading when the count reaches it: it
    // is what this handle saw at open, and the copy below is correct whether
    // or not the file is still that length.
    let hint = file.len();

    // The adapter carries the cursor and pipelines its reads ahead of you,
    // whatever size `copy` happens to ask for — which is 8 KiB, far too small
    // to be worth a round trip each on its own.
    let mut reader = file.into_reader();

    let copied = match &local {
        Some(destination) => {
            let mut out = tokio::fs::File::create(destination).await?;
            let copied = tokio::io::copy(&mut reader, &mut out).await?;
            out.flush().await?;
            copied
        }
        None => tokio::io::copy(&mut reader, &mut tokio::io::sink()).await?,
    };

    println!(
        "{remote}: streamed {copied} bytes (len() at open said {hint}){}",
        local.map(|to| format!(" to {to}")).unwrap_or_default()
    );

    // The adapter owns the file. Take it back to close it properly and hear
    // whether the release succeeded — dropping the reader releases the handle
    // best-effort and cannot report anything.
    reader.into_inner().await?.close().await?;

    client.close().await?;
    Ok(())
}
