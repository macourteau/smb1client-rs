//! Walk a share depth-first, and close each listing before moving on.
//!
//! Listing is lazy: `read_dir` issues one request and the iterator pages in the
//! rest as you drain it. That laziness is what makes closing matter. The
//! iterator owns a search the *server* is holding open, and while it is open
//! the server may refuse or misreport operations on the directory it is
//! enumerating.
//!
//! ```text
//! cargo run --example walk_tree -- '\\127.0.0.1:10445\testshare' smbtest smbtest
//! cargo run --example walk_tree -- '\\host\share' user pass subdir 5000
//! ```

use std::process::ExitCode;

use smb1client::{Client, ClientConfig, Credentials, Tree, UncPath};

/// How many entries to print before stopping, so that pointing this at an
/// unfamiliar server is not an open-ended commitment.
const DEFAULT_LIMIT: usize = 500;

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
            "usage: walk_tree <\\\\host[:port]\\share> <user> <password> [start] [limit]".into(),
        );
    };
    let start = arguments.next().unwrap_or_default();
    let limit = match arguments.next() {
        Some(limit) => limit.parse()?,
        None => DEFAULT_LIMIT,
    };

    let unc: UncPath = unc.parse()?;
    let client = Client::new(ClientConfig {
        allow_guest: std::env::var_os("SMB1_ALLOW_GUEST").is_some(),
        ..ClientConfig::new(Credentials::new(user, password))
    });
    let tree = client.tree(&unc).await?;

    let mut seen = 0;
    // An explicit stack rather than recursion, which in async Rust would mean
    // boxing the future at every level. It also makes the shape of the walk
    // obvious: one directory open at a time, and never a listing held across
    // the work done on what it returned.
    let mut pending = vec![start];
    while let Some(directory) = pending.pop() {
        let children = list(&tree, &directory, limit - seen).await?;
        for (name, is_dir) in children {
            let full = join(&directory, &name);
            println!("{}{full}", if is_dir { "d " } else { "  " });
            seen += 1;
            if is_dir {
                pending.push(full);
            }
        }
        if seen >= limit {
            println!("stopped at {limit} entries");
            break;
        }
    }

    client.close().await?;
    Ok(())
}

/// Drains one directory's listing and closes it before returning.
///
/// Draining into a `Vec` first is the point, not an accident of style. Anything
/// that acts on what a listing returned — descending into it, deleting it,
/// renaming it — must happen after the search is *released*, and releasing it
/// is a round trip you have to await. Dropping the iterator enqueues the same
/// close best-effort, which means the next request may reach the server first;
/// on some servers a still-open search on a directory turns the delete that
/// follows into a permission error, after the contents are already gone.
async fn list(
    tree: &Tree,
    directory: &str,
    remaining: usize,
) -> smb1client::Result<Vec<(String, bool)>> {
    let mut listing = tree.read_dir(directory).await?;
    let mut entries = Vec::new();
    while let Some(entry) = listing.next_entry().await? {
        entries.push((entry.name().to_owned(), entry.is_dir()));
        if entries.len() >= remaining {
            // Stopping early is exactly the case `close()` is a real round trip
            // for: a listing drained to its end was already released by the
            // server, and this one was not.
            break;
        }
    }
    listing.close().await?;
    Ok(entries)
    // One thing no amount of closing buys you: mutating a directory while an
    // enumeration over it is still open is not safe on any SMB1 server.
    // Entries may be skipped or repeated, and no two servers need agree on
    // which. Finish the listing, then act.
}

/// Joins a directory to an entry name. `/` would work as well as `\` — both are
/// accepted and normalized — but the wire form is the backslash.
fn join(directory: &str, name: &str) -> String {
    if directory.is_empty() {
        name.to_owned()
    } else {
        format!("{directory}\\{name}")
    }
}
