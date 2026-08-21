# The acceptance container

This is the entire automatic acceptance gate. It is pinned by image digest and
by exact package version, and `.github/dependabot.yml` excludes it from
dependency updates.

That exclusion is the point rather than an oversight. Some distributions build
Samba without the SMB1 server, and upstream is actively removing SMB1 server
support. An automerged base-image bump that silently produced a container which
no longer speaks NT1 would **delete the acceptance oracle rather than fail
loudly** — every test would go on passing against a server that no longer
exercises the dialect this crate exists for.

There is no consumer exposure here and no advisory pressure: nothing this
container runs ships to anyone. So there is no reason to update it except
deliberately.

**To update it deliberately**, change the digest and the package version
together, then confirm the container still speaks NT1 before committing:

```sh
docker build -t smb1client-acceptance .ci/samba
docker run --rm -d --name smb1client-acceptance -p 10445:445 smb1client-acceptance
docker exec smb1client-acceptance /usr/local/bin/seed.sh
docker exec smb1client-acceptance /usr/local/bin/assert-nt1.sh
```

`assert-nt1.sh` is the gate, and it must not be replaced by an `smbclient`
invocation whose exit status is read. Two traps, both observed against Samba
4.23.8 rather than reasoned about:

- `smbclient -m NT1` alone is an **invalid parameter mix**, because modern Samba
  defaults `client min protocol` to SMB2_02 and capping the maximum at NT1 asks
  for a protocol between SMB2_02 and NT1. The client refuses before reaching the
  network, so the check fails against a perfectly good server.
- **`smbclient` exits 0 when protocol negotiation fails.** A check reading its
  exit status therefore passes against a server that has lost SMB1 entirely —
  the exact silent degradation this pinning exists to prevent, arriving through
  the check meant to detect it.

The definition originates in the Go reference library's `integration/`
directory, which floats on both counts. This copy exists because the crate's CI
checks out the crate and nothing else, so reaching across is not available to
it.
