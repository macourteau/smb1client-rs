//! Connect to a share and list a directory: the whole opening sequence.
//!
//! `Client` → `Tree` → the listing, and there is nothing else in between.
//! There is no connection object and no session object to hold; the client
//! dials, authenticates and caches those behind the `Tree` it hands back.
//!
//! ```text
//! cargo run --example list_dir -- '\\127.0.0.1:10445\testshare' smbtest smbtest
//! cargo run --example list_dir -- '\\127.0.0.1:10445\testshare' smbtest smbtest subdir
//! ```

use std::process::ExitCode;

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
    let (Some(unc), Some(user), Some(password)) =
        (arguments.next(), arguments.next(), arguments.next())
    else {
        return Err(
            "usage: list_dir <\\\\host[:port]\\share> <user> <password> [directory]".into(),
        );
    };
    // Share-relative, and the empty string is the share root. Paths here are
    // `&str` rather than `std::path::Path`, because a remote path is not a
    // local one: `/` and `\` are both accepted and normalized to the backslash
    // the wire wants, whatever platform the client is running on.
    let directory = arguments.next().unwrap_or_default();

    // `\\server\share`, optionally `\\server:port\share`. This is the only
    // address anything in the API carries.
    let path: UncPath = unc.parse()?;

    let client = Client::new(ClientConfig {
        allow_guest: std::env::var_os("SMB1_ALLOW_GUEST").is_some(),
        ..ClientConfig::new(Credentials::new(user, password))
    });

    // Dials the server, authenticates, connects the tree — or reuses a
    // connection this client already has to that server, which is what makes
    // calling this per operation cheap instead of wasteful.
    let tree = client.tree(&path).await?;

    // Listing is lazy: this issues one request and hands back an iterator that
    // fetches further pages as it is drained. `.` and `..` are filtered out,
    // matching `std::fs::read_dir`. Entry order is whatever the server sent —
    // Samba does not sort and Windows does, and nothing obliges either.
    let mut listing = tree.read_dir(&directory).await?;
    let mut count = 0;
    while let Some(entry) = listing.next_entry().await? {
        let modified = entry
            .modified()
            .map(|when| when.to_string())
            .unwrap_or_else(|| "-".to_owned());
        println!(
            "{} {:>12} {:<28} {}",
            if entry.is_dir() { 'd' } else { '-' },
            entry.len(),
            modified,
            entry.name()
        );
        count += 1;
    }
    println!("{count} entries");

    // This listing was drained to the end, so the server released the search
    // itself and `close()` sends nothing and cannot fail. Closing anyway is
    // the habit worth having: see `walk_tree.rs` for the case where it is a
    // real round trip and skipping it breaks the operation that follows.
    listing.close().await?;

    // Note there is no `tree.close()` here. The tree belongs to the client's
    // cache and is shared with every other caller that asked for the same
    // share, so closing it would return `Ok` having sent nothing. Releasing
    // the tree is the client's job, and this is where it happens.
    client.close().await?;
    Ok(())
}
