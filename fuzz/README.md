# Fuzz targets

The four parsers an unauthenticated peer can reach: the frame decoder, the
negotiate-response parser, the SPNEGO decoder, and the NTLM challenge parser,
which consumes server-supplied AV pairs before authentication has completed.

They are not a trust boundary, because the crate has none to draw: it does not
sign, so it never authenticates the server at any point, and a hostile or
intermediary peer is exactly as present after the session setup as before it.
These four are where hardening starts.

Each target is a thin wrapper over one `#[doc(hidden)] pub` entry point in
`smb1client::fuzz`. That is deliberate and is not a feature flag: a flag would
add a second build configuration for CI to test, when the point is that the
fuzzers drive the same code path a consumer gets. Publishing `wire` instead
would make every message type API.

```sh
cargo +nightly fuzz run frame
cargo +nightly fuzz run negotiate_response
cargo +nightly fuzz run spnego
cargo +nightly fuzz run ntlm_challenge
```

`.github/workflows/fuzz.yml` runs all four weekly on the nightly toolchain, from
the seed corpus in `corpus/`. They are deliberately not a pull-request check:
fuzzing on a pull request either finds nothing within the budget it is given or
blocks a merge on a run nobody sized for it.

`corpus/` is a **seed** corpus, kept small on purpose. The seeds are real
negotiate frames from the committed fixture corpus and real SPNEGO and NTLM
messages from the committed vectors — no captured session-setup frame is here,
or anywhere else in this repository, because one carries an offline-crackable
NTLMv2 handshake. Inputs a run discovers are not committed back.
