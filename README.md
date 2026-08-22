# smb1client

An asynchronous SMB1/CIFS client for Rust, for talking to legacy file servers
that speak nothing newer.

SMB1 is frozen and deprecated, and that is the point: some servers still speak
nothing else. Nothing in the Rust ecosystem covers the dialect — the canonical
SMB crate implements SMB2/SMB3 only, and the most-downloaded alternative is a
GPLv3 FFI wrapper around libsmbclient — so this is a port of a pure-Go SMB1
library, written to keep the same servers reachable from Rust.

> **Status: pre-1.0.** The API is implemented and exercised against four SMB1
> servers. It stays below 1.0 until a real consumer has exercised it, and Cargo
> treats every `0.x` minor as incompatible — so a breaking change arrives as a
> minor bump, and the resolver is what protects a dependency rather than review.

## Security — read this before pointing it at anything

**This crate does not sign messages, and SMB1 has no encryption at all.** The
first is deliberately deferred; the second the protocol does not offer. Two
consequences follow:

- **Every byte on the connection is in the clear**, including file contents and
  the paths that name them. Anyone on the network path reads them.
- **The server is never authenticated.** Without signing there is no way to
  establish that the peer answering is the server that was dialled, at any point
  in the connection's life. A hostile or intermediary peer is exactly as present
  after the session setup as before it.

Authentication is NTLMv2, which does protect the password from anyone merely
reading the wire. What it does not do is protect the session that follows. Treat
an SMB1 connection as a plaintext channel to an unverified peer, and put it on a
network where that is acceptable.

The crate is `#![forbid(unsafe_code)]`, every parser an unauthenticated peer can
reach carries a fuzz target, and allocation from untrusted input is bounded
wherever it happens.

## Usage

```toml
[dependencies]
smb1client = "0.1"
```

A caller reaches a file through `Client` → `Tree` → `File`, and that is the
whole opening sequence. `examples/` carries a progression, smallest first, and
each one is commented where the contract is easy to get subtly wrong:

| Example | What it shows |
| --- | --- |
| `list_shares` | Enumerating a server's shares, which needs no share and so comes first in a real program. |
| `list_dir` | The opening sequence, and a lazy listing drained to its end. |
| `read_file` | The whole-file helper, `read_exact_at` on a span, `len()` as a hint, and `Error::kind()` beside `Error::status()`. |
| `write_file` | Writing, and reading `WriteProgress` after a cancelled write — the only way to learn what landed. |
| `stream_file` | The `AsyncRead` adapter and `tokio::io::copy`, for a file too large to hold in memory. |
| `walk_tree` | Walking, and closing each listing before acting on what it returned. |

```sh
cargo run --example list_dir -- '\\127.0.0.1:10445\testshare' smbtest smbtest
```

Every one takes its server, credentials and paths as arguments. `write_file` is
the only one that writes, and it creates and then deletes a single obviously
named file. Set `SMB1_ALLOW_GUEST=1` for a server that maps the logon to guest,
which the crate refuses by default so that a rejected login cannot pass for a
successful one.

## Design

The crate is async-only, on [tokio]. SMB1 is a multiplexed protocol — requests
carry a 16-bit multiplex ID and responses return out of order — so something has
to read frames continuously and route each to whichever caller is waiting. Here
that is one task per connection, owning the socket and the table of outstanding
requests outright; callers hold cheap handles and await replies, and cancelling
is dropping a future. A synchronous caller must either adopt a runtime or block
on the futures itself.

`docs/design/2026-08-20-rust-port.md` is the decision record the implementation
follows. It is unusually detailed on purpose: much of SMB1's behaviour here was
measured against real servers rather than read off a specification, and the
document records which numbers were measured, which were chosen, and which are
inherited from the Go original without a derivation. Anyone changing behaviour
should read it first.

## Compatibility

Exercised against three SMB1 servers — a Samba container, an embedded device and
Windows 11 24H2 — with the wire evidence committed as fixtures under `fixtures/`
and asserted in CI. Two of those are Samba-family, so the corpus covers two
implementations rather than three, and several late defects surfaced only
against Windows.

TCP port 445 only; port 139 NetBIOS session transport is a non-goal. A server is
reachable over IPv6 only by a hostname that resolves to one, SMB1's UNC syntax
admitting no literal form.

## Checking a server of your own

Some of what this crate does turns on what a *particular* server makes of a wire
choice it sends and the Go original never did, and no committed evidence can
settle those. `examples/conformance.rs` carries them, run by hand rather than in
CI:

```sh
cargo run --example conformance -- \
    --server 192.168.0.10 --share testshare --user smbtest --password secret
```

It prints, for each check, what it asserts, what the server did, and a verdict —
and says a check is unrunnable rather than passing it where that server cannot
exercise it. Add `--read-only` against a server holding data that matters: it
then creates, modifies and deletes nothing, and skips the checks that would have
written. Run one instance at a time against Windows, which does not take kindly
to a second SMB1 handshake from a host that already has one open.

## Licence

`MIT OR Apache-2.0`.

[tokio]: https://docs.rs/tokio
