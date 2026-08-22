//! Read a file three ways, and read an error properly when one fails.
//!
//! The three ways are not interchangeable, and choosing between them is most
//! of what there is to learn about reading with this crate:
//!
//! - `Tree::read` for a file you know is small,
//! - `File::read_exact_at` for a span whose length you already know,
//! - the reader adapter (see `stream_file.rs`) for anything else.
//!
//! ```text
//! cargo run --example read_file -- '\\127.0.0.1:10445\testshare' smbtest smbtest alpha.txt
//! ```

use std::process::ExitCode;

use smb1client::{Client, ClientConfig, Credentials, Error, UncPath};

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
        return Err("usage: read_file <\\\\host[:port]\\share> <user> <password> [path]".into());
    };
    let path = arguments.next().unwrap_or_else(|| "alpha.txt".to_owned());

    let unc: UncPath = unc.parse()?;
    let client = Client::new(ClientConfig {
        allow_guest: std::env::var_os("SMB1_ALLOW_GUEST").is_some(),
        ..ClientConfig::new(Credentials::new(user, password))
    });
    let tree = client.tree(&unc).await?;

    // The whole-file helper. It exists so the fill-or-error read loop lives in
    // one tested place instead of in every consumer, and because it hands the
    // transport the entire payload at once — a caller looping in 64 KiB chunks
    // never reaches the size at which this crate starts pipelining requests,
    // however large the file is, so the hand-rolled loop is also the slow one.
    //
    // It is for files you know are small: it allocates the whole thing. It is
    // also the one place the fill-or-error rule below does not apply — a file
    // another writer truncates mid-read answers short, and that is end of file
    // here rather than an error.
    match tree.read(&path).await {
        Ok(bytes) => {
            println!("{path}: {} bytes", bytes.len());
            for line in String::from_utf8_lossy(&bytes).lines().take(3) {
                println!("  | {line}");
            }
        }
        Err(error) => report(&path, &error),
    }

    // The handle form, for a span rather than the whole file.
    let file = tree.open(&path).await?;

    // `len()` is infallible and synchronous because the open already reported
    // it — no round trip. It is a hint and never a gate: do not use it to
    // decide whether a read is worth issuing or to short-circuit one, because
    // it is this handle's stale view and another writer may have moved it.
    // `Tree::metadata` is what goes to the server for a fresh answer.
    println!("{path}: len() reports {} at open", file.len());

    // `read_exact_at` fills the buffer or fails. There is no count to check
    // and no short read to overlook: asking for bytes the file does not hold
    // is an error, not a smaller number you have to remember to notice. A
    // caller that wants a count reads through the adapter instead, where
    // `AsyncRead` reports end of file the way it does everywhere.
    let mut head = vec![0u8; 8];
    match file.read_exact_at(&mut head, 0).await {
        Ok(()) => println!("first 8 bytes: {head:02x?}"),
        Err(error) => report("read_exact_at", &error),
    }

    // Deliberately starting at the end, so there is nothing to fill with.
    // This is what "cannot fill" looks like: an error, and never a zero you
    // could mistake for a successful read of nothing.
    if let Err(error) = file.read_exact_at(&mut head, file.len()).await {
        report("a read starting at the end", &error);
    }

    // `close()` consumes the handle — using a closed one is a compile error —
    // and reports whether the release round trip succeeded. Dropping the file
    // releases it too, but best-effort: `Drop` can neither await the reply nor
    // return an error, so a drop cannot tell you the server did not hear, and
    // cannot promise the release has happened before your next call runs.
    file.close().await?;

    // A path that is certainly not there, so the error path has something to
    // show.
    if let Err(error) = tree.read("no-such-file-smb1client-example").await {
        report("a missing file", &error);
    }

    client.close().await?;
    Ok(())
}

/// Prints what a failure was, both ways round.
fn report(operation: &str, error: &Error) {
    // `kind()` is the portable question. "Did this fail because it is not
    // there?" is four different NT statuses depending on which server
    // answered, and all four arrive here as `ErrorKind::NotFound`. Match on
    // this, not on the status, whenever the kind can express what you mean.
    print!("{operation}: {error}\n  kind: {:?}", error.kind());

    // `status()` is the raw NT status, for what `kind()` cannot express — most
    // statuses classify to `ErrorKind::Other`, so this is where the detail
    // survives. It is `None` where the failure never carried a status at all —
    // a transport failure, anything refused before it reached the wire, and
    // the read above, whose failure was the crate's own verdict on what came
    // back rather than the server's refusal to answer.
    match error.status() {
        Some(status) => println!(", status: {status}"),
        None => println!(", no status (this failure did not come from one)"),
    }
}
