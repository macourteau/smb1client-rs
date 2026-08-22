//! Write a file, and learn how much of a cancelled write actually landed.
//!
//! **This example creates and then deletes a file on the share.** It writes to
//! `smb1client-example.txt` at the share root unless you name another path, so
//! that running it against a share holding real data is not a surprise.
//!
//! ```text
//! cargo run --example write_file -- '\\127.0.0.1:10445\testshare' smbtest smbtest
//! cargo run --example write_file -- '\\host\share' user pass scratch/mine.txt
//! ```

use std::process::ExitCode;
use std::time::Duration;

use tokio::io::AsyncWriteExt;

use smb1client::{Client, ClientConfig, Credentials, UncPath, WriteProgress};

/// Big enough that a cancellation lands in the middle of it rather than
/// before it starts or after it finishes.
const LARGE: usize = 8 * 1024 * 1024;

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
        return Err("usage: write_file <\\\\host[:port]\\share> <user> <password> [path]".into());
    };
    let path = arguments
        .next()
        .unwrap_or_else(|| "smb1client-example.txt".to_owned());

    let unc: UncPath = unc.parse()?;
    let client = Client::new(ClientConfig {
        allow_guest: std::env::var_os("SMB1_ALLOW_GUEST").is_some(),
        ..ClientConfig::new(Credentials::new(user, password))
    });
    let tree = client.tree(&unc).await?;

    // The whole-file helper, which creates the file or truncates what is there,
    // exactly as `std::fs::write` does. Like `Tree::read`, it exists so the
    // loop lives in one tested place and so the transport is handed the whole
    // payload at once.
    tree.write(&path, b"written by the smb1client write_file example\n")
        .await?;
    println!("wrote {path}: {} bytes", tree.metadata(&path).await?.len());

    // The `AsyncWrite` adapter, for a source you would rather stream than hold
    // in memory. `into_writer` takes its optional `WriteProgress` here rather
    // than per call, because `AsyncWrite::poll_write` has nowhere to put one
    // and an adapter is built once — and it returns a `Result` for that
    // argument's sake.
    let mut writer = tree.create(&path).await?.into_writer(None)?;
    let mut source = &b"streamed in through the AsyncWrite adapter\n"[..];
    tokio::io::copy(&mut source, &mut writer).await?;
    // `shutdown` flushes what the adapter has buffered. `into_inner` gives the
    // `File` back and flushes too, and both can fail, because an infallible
    // synchronous handback would discard buffered bytes with nothing returned
    // to say so.
    writer.shutdown().await?;
    let file = writer.into_inner().await?;
    file.close().await?;
    println!("wrote {path}: {} bytes", tree.metadata(&path).await?.len());

    // Now the part that is easy to get wrong.
    //
    // Cancelling an async operation in Rust means dropping its future, and a
    // dropped future yields *nothing at all* — no count, no error. So a
    // cancelled write can tell you nothing about how much of it reached the
    // server, unless something that outlives the future was holding the
    // answer. That is what `WriteProgress` is: the caller keeps a clone and
    // passes another to the call **by value**, because a borrow is the one
    // shape that could not outlive the future it was lent to.
    let progress = WriteProgress::new();
    let file = tree.create(&path).await?;
    let data = vec![b'x'; LARGE];
    let cancelled = tokio::time::timeout(
        Duration::from_millis(5),
        file.write_all_at(&data, 0, Some(progress.clone())),
    )
    .await;

    match cancelled {
        Ok(outcome) => {
            outcome?;
            println!("the write finished before the timeout: {LARGE} bytes");
        }
        Err(_) => {
            // The future is gone, but its chunks may still be in flight.
            // `completed()` waits for the last of them to leave; reading
            // `written()` before that returns a number still growing, which is
            // the wrong thing to resume from.
            progress.completed().await;
            // The contiguous acknowledged prefix, and a lower bound on what
            // reached the server. Not a total: replies land out of order, so
            // if a middle chunk failed while later ones succeeded the two
            // differ, and only the prefix is safe to resume from.
            println!(
                "the write was cancelled; {} of {LARGE} bytes are on the server",
                progress.written()
            );
        }
    }
    // One `WriteProgress` serves one write for its whole lifetime, not one at a
    // time: a prefix computed across two writes to different offsets means
    // nothing. A second write constructs a second handle.
    file.close().await?;

    tree.remove_file(&path).await?;
    println!("removed {path}");

    client.close().await?;
    Ok(())
}
