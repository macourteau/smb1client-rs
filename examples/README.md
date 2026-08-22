# Examples

Read them in the order below. Each is small, runnable, and takes its target from
the command line, so nothing writes to a share you did not name.

```sh
cargo run --example list_shares -- <server> <user> <password>
```

Set `SMB1_ALLOW_GUEST=1` where the server maps your logon to guest — the crate
refuses that by default, because on many servers a guest logon is exactly what a
wrong password produces, and every later operation would silently run as an
anonymous user.

| Example | Start here if you want to know |
|---|---|
| `list_shares` | What a server offers. Needs no share, so it is what a real program does first. |
| `list_dir` | The whole opening sequence: `Client` → `Tree` → a listing. |
| `read_file` | The three ways to read, and which one to reach for. |
| `write_file` | Writing, and what happens to a write you cancel. |
| `stream_file` | Moving a large file with `tokio::io::copy`. |
| `walk_tree` | Descending a share, and why a listing gets closed rather than dropped. |

`conformance.rs` is not one of these. It is a diagnostic that points nine
protocol checks at a server of your own and reports what it did — useful before
trusting this crate against an SMB1 server nobody here has tried, and a poor
first thing to read. The main README describes it.

## The five things worth taking away

These are the contracts that are easy to get subtly wrong, and each example
shows one rather than explaining it.

**`close()` reports failure; dropping cannot.** Releasing a handle is a network
round trip, and Rust's `Drop` can neither await one nor report that it failed.
So `close()` consumes the handle and returns a `Result`, and dropping enqueues a
best-effort close instead. Use `close()` wherever the release actually matters —
above all before doing something that depends on it having happened.

**`read_exact_at` fills the buffer or fails.** There is no count to check and no
short read to notice, because a short read a caller must remember to check is
the same silent truncation moved from the library into every consumer. Reading
past the end of a file is an error, not a zero. If you want a count, read through
`into_reader()`, which reports end of file the way `AsyncRead` does everywhere.

**`len()` is a hint, never a gate.** It comes free with the open and is updated
as you write, so it costs nothing — but another writer can extend or truncate
the file at any moment. Never decide *not* to read because `len()` said so; ask
the server and handle the answer. `metadata()` goes and looks when you need to
be sure.

**A cancelled write cannot tell you anything by itself.** Drop a write future and
it yields no value at all: no count, no error. That is why `write_all_at` takes
an optional `WriteProgress` **by value** — it has to outlive the future it was
passed to. Afterwards, `completed().await` tells you every chunk has stopped
moving and `written()` gives the contiguous acknowledged prefix, which is the
only number safe to resume from. `write_file` shows the whole shape in about ten
lines.

**One `Client` is one identity, and it caches.** It holds connections, sessions
and trees internally and hands out cheap handles, so build one and share it.
Building a `Client` per operation throws away the connection each time and
re-authenticates. Two sets of credentials mean two `Client`s.

## Running them against something real

Anything writing takes a path argument and writes only there. `walk_tree` and
`list_dir` take a limit so pointing them at a large share does not print for
ever.

Two server behaviours will surprise you before this crate does:

- **Windows allows one SMB1 connection per client host at a time.** Run one
  example at a time against it. Dialled in parallel the later handshakes break;
  dialled back to back they succeed, but the earlier connection is already dead.
- **Entry order is the server's.** Windows sorts a directory and Samba does not.
  Sort before comparing if order matters to you.
