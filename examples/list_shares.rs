//! Ask a server what shares it offers.
//!
//! This is the first example rather than the fourth because it is the first
//! thing a real program does: enumerating names no share and needs no `Tree`,
//! which is exactly the position a program is in before it knows what to
//! connect to.
//!
//! ```text
//! cargo run --example list_shares -- 127.0.0.1:10445 smbtest smbtest
//! ```

use std::process::ExitCode;

use smb1client::{Client, ClientConfig, Credentials, Server};

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
    let (Some(server), Some(user), Some(password)) =
        (arguments.next(), arguments.next(), arguments.next())
    else {
        return Err("usage: list_shares <host[:port]> <user> <password>".into());
    };

    // A server is a host and an optional port. 445 is the default, and a port
    // is only ever a dialling instruction: it never reaches the wire.
    let server: Server = server.parse()?;

    // One `Client` is one identity. The credentials live on the config rather
    // than on any call, so every connection this client dials authenticates
    // with the same material and a program needing two identities builds two
    // clients. It caches connections and trees internally and every method
    // takes `&self`, so build one, share it across tasks behind an `Arc` if you
    // like, and never build a second for the same credentials just because a
    // second operation came along.
    let client = Client::new(ClientConfig {
        // Off by default, and deliberately: a server that quietly maps a
        // rejected login to guest would otherwise look like a successful one.
        // The public test servers here are guest-mapped, so opt in for them.
        allow_guest: std::env::var_os("SMB1_ALLOW_GUEST").is_some(),
        ..ClientConfig::new(Credentials::new(user, password))
    });

    // One call, two transports: RAP is tried first and DCE/RPC `srvsvc`
    // answers where it cannot — Windows serves no RAP at all. Which one
    // answered is not something a caller can see, and is not meant to be.
    for share in client.list_shares(&server).await? {
        let mut notes = Vec::new();
        if share.kind.special {
            notes.push("special");
        }
        if share.kind.temporary {
            notes.push("temporary");
        }
        println!(
            "{:<20} {:<12} {:<20} {}",
            share.name,
            format!("{:?}", share.kind.service),
            notes.join(","),
            share.comment
        );
    }

    // `close()` awaits the goodbye — a `TREE_DISCONNECT` per tree and a
    // `LOGOFF_ANDX` — and reports whether the server was actually told.
    // Dropping the client says the same goodbye best-effort and has no way to
    // report a failure, because `Drop` can neither await nor return an error.
    client.close().await?;
    Ok(())
}
