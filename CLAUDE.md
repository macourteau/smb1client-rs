# smb1client-rs

A pure-Rust asynchronous SMB1/CIFS client, ported from the Go library
`github.com/macourteau/smb1client`. The Go reference is pinned at `b948f59`.

## The design record is the source of truth

`docs/design/2026-08-20-rust-port.md`.

This crate was designed before it was written, and that document is a decision
record rather than a specification: it says not only what each piece does but
why, and which alternatives were argued over and rejected. It rests on an
evidence campaign against three SMB1 server implementations — a wire-fixture
corpus and a spike log behind every measured number in it — which is kept with
the authoritative copy of the document, in the repository the fixtures under
`fixtures/` are copied from.

That file is **generated and never hand-edited**. Amend the authoritative
document, re-sync, and commit both sides; an edit made here is lost on the next
sync and, worse, makes the two disagree in the meantime.

Read it before changing behaviour. Where a decision turns out wrong, **revise
that document rather than working around it**: the first unrecorded deviation is
the moment it stops being the source of truth, and every later session inherits
the lie.

Two of its rules are easy to violate by accident:

- **Correctness outranks fidelity to the Go original.** Where that library is
  known-good it is the reference implementation and the differential oracle. It
  is not everywhere: the design record enumerates twenty-two behaviours where the
  Go library is wrong, and for each the test suite asserts the correct result
  instead of reproducing it.
- **Idiomatic Rust outranks faithful translation.** This crate is maintained by
  someone whose expertise is not Rust, so code that reads as ordinary Rust to
  any Rust programmer is worth more than code mirroring the Go source's shape.

## Local verification — run this before pushing

CI minutes are billed, and every one of these runs locally:

```sh
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo test --locked
RUSTDOCFLAGS="-D warnings" cargo doc --no-deps
cargo package --locked
cargo deny check
actionlint
```

`actionlint` is not optional tidiness. A YAML parser accepts a workflow whose
**expressions** are invalid — GitHub Actions expressions allow single-quoted
strings only, and a double-quoted one is a file-level syntax error. GitHub then
rejects the whole workflow before any job starts, and the failure carries no
job, no log and a zero duration, so there is nothing to read. `actionlint`
catches that class locally.

**Check which clippy answers before trusting a clean run.** `cargo clippy`
resolves `cargo-clippy` from `PATH`, so a package-manager copy shadows rustup's
even under `rustup run` — which means a stale clippy can report a clean tree
that CI then rejects on lints it never knew about. `cargo clippy --version`
should match the toolchain CI pins in `.github/workflows/ci.yml`. If it does
not, put that toolchain's own directory in front, located through rustup:

```sh
PATH="$(dirname "$(rustup which --toolchain stable cargo-clippy)"):$PATH" \
  cargo clippy --all-targets -- -D warnings
```

**Two shorter fixes do not work, and both look like they do.**
`rustup run <toolchain> cargo clippy` still resolves `cargo-clippy` from `PATH`,
so it runs the shadowing one under a correct `rustc`. And
`export PATH="$(rustc --print sysroot)/bin:$PATH"` asks the *shadowing* `rustc`
for its sysroot and therefore puts the stale toolchain first — it entrenches the
problem while appearing to solve it. Always read `cargo clippy --version` back
before believing a clean run.

The MSRV leg. This is the only thing that checks the crate's own code compiles
on the floor it declares — the 2024 edition's resolver is MSRV-aware for
dependency *selection* only, so without it the declared version is an unverified
claim and a consumer is the one who discovers the lie:

```sh
MSRV=$(sed -n 's/^rust-version *= *"\(.*\)"/\1/p' Cargo.toml)
rustup toolchain install "$MSRV"
rustup run "$MSRV" cargo check --all-targets --locked
```

`rustup run` rather than `cargo +$MSRV`: the `+toolchain` directive is handled
by rustup's `cargo` shim, so it fails outright wherever another `cargo` — a
Homebrew one, for instance — comes first on `PATH`.

The acceptance suite. The container has to be seeded rather than merely running:
the checks assert against seeded content, so an unseeded share would degrade the
oracle to something that passes without testing anything.

```sh
docker build -t smb1client-acceptance .ci/samba
docker run -d --name smb1client-acceptance -p 10445:445 smb1client-acceptance
docker exec smb1client-acceptance /usr/local/bin/seed.sh
docker exec smb1client-acceptance /usr/local/bin/assert-nt1.sh
SMB1_TEST_SERVER=127.0.0.1:10445 SMB1_TEST_SHARE=testshare \
SMB1_TEST_USER=smbtest SMB1_TEST_PASSWORD=smbtest \
SMB1_TEST_SEEDED_DIR=bigdir SMB1_TEST_SEEDED_COUNT=600 \
SMB1_TEST_EMPTY_DIR=emptydir SMB1_TEST_READ_FILE=alpha.txt \
  cargo test --locked -- --include-ignored
```

**The seeded variables are not optional here.** Without them the two live checks
the design names — a listing of the 600-entry directory returning 600, and an
empty directory returning no entries and no error — print a line saying they were
skipped and then report `ok`. That is right for a developer pointing the suite at
an arbitrary server and wrong for an acceptance run: you get a green result that
never exercised either. The CI job sets them and greps its own output to prove
they ran; a local run has only this line to rely on.

`assert-nt1.sh` is not decoration and must not be replaced by an `smbclient`
invocation that reads its exit status: **smbclient exits 0 when protocol
negotiation fails**, so the naive check passes against a container that has lost
SMB1 entirely. The script says why in full.

## Commit convention

`release-plz` computes the version from Conventional Commits, so the prefix is
release policy rather than style:

| Prefix | Effect |
|---|---|
| `feat:` | minor bump |
| `fix:` | patch bump |
| `!` or `BREAKING CHANGE:` | major bump — see the pre-1.0 note below |
| `ci:` `docs:` `test:` `refactor:` `chore:` | no release |

**That last row is configuration, not a property of `release-plz`.** Its default
bumps a patch for any unreleased commit whatever the prefix, so a `docs:` commit
opens a release pull request that auto-merge then ships. What holds the row is
the `release_commits` regex in `release-plz.toml`; editing that regex edits
release policy. Its `!` alternative is deliberate — a breaking change is marked
by the `!` and not by the type carrying it, so `refactor!:` releases while
`refactor:` does not. `commit_parsers` with `skip = true` is not a substitute:
it groups the changelog and leaves the version bump alone.

Mark a breaking change with `!` in the subject. Whether a bare `BREAKING CHANGE:`
trailer in the body reaches the release gate is unverified here, and the `!` is
what the regex matches.

**A releasable change without a `feat:` or `fix:` prefix never ships.** Nobody
approves a release: `release-plz` opens a pull request, CI gates it, and
auto-merge lands it, so the commit message is the only place version discipline
lives.

The crate stays pre-1.0 until its API has been exercised by a real consumer.
Under Cargo's semantics every `0.x` minor is incompatible, so a breaking change
is a minor bump, and what protects a consumer from an unreviewed breaking
release is the resolver rather than review.

## House rules

- **No AI attribution anywhere** — commit messages, code, comments, docs, pull
  request bodies. Strip harness-added trailers.
- **No "new" or "now" language** in code or documentation. Write as if the code
  has always been this way; the changelog carries history.
- Comments explain *why*. The design record holds the long-form reasoning; a
  comment here states the reason rather than restating the document.
- `unsafe_code` is forbidden and `missing_docs` warns, both set in `Cargo.toml`.
- `Cargo.lock` is committed deliberately. `.gitignore` says why.
