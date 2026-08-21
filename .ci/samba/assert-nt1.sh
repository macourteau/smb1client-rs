#!/bin/sh
# Prove the container still speaks NT1, and fail loudly when it does not.
#
# Two traps make the obvious check useless, and both were observed against
# Samba 4.23.8 rather than reasoned about:
#
# 1. `smbclient -m NT1` alone is an invalid parameter mix. Modern Samba defaults
#    `client min protocol` to SMB2_02, so capping the maximum at NT1 asks for a
#    protocol between SMB2_02 and NT1 and the client refuses before reaching the
#    network. `--option='client min protocol=NT1'` is what lowers the floor.
#
# 2. **smbclient exits 0 when protocol negotiation fails.** A check that reads
#    the exit status passes against a server that has lost SMB1 entirely — which
#    is the exact failure this container exists to make impossible. The verdict
#    therefore comes from the output, never from the status.
#
# The distribution matters here: some build Samba with --without-smb1-server,
# and upstream is actively removing SMB1 server support. This script is what
# stands between that and an acceptance gate that passes without testing
# anything.
set -eu

out=$(smbclient //127.0.0.1/testshare -U smbtest%smbtest \
        -m NT1 --option='client min protocol=NT1' -c 'ls' 2>&1 || true)

if printf '%s' "$out" | grep -qiE 'negotiation to server|no compatible protocol|NT_STATUS_'; then
  echo "The container does not speak NT1. SMB1 is gone from this image:" >&2
  printf '%s\n' "$out" >&2
  exit 1
fi

# A successful negotiation that returned no directory is still a failure: it
# would mean the share is unreachable or unseeded, and every acceptance check
# below asserts against seeded content.
if ! printf '%s' "$out" | grep -q 'alpha.txt'; then
  echo "NT1 negotiated but the share does not hold the seeded content:" >&2
  printf '%s\n' "$out" >&2
  exit 1
fi

echo "NT1 confirmed against $(smbd --version)"
