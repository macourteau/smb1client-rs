#!/bin/sh
# Seed the share with the content the acceptance checks are written against.
#
# This runs as a step of the acceptance job, not as a layer of the image: the
# design document requires the oracle to be seeded rather than merely running,
# so that it cannot quietly degrade to an empty share.
set -eu

rm -rf /srv/testshare/* /srv/testshare/.[!.]* 2>/dev/null || true

printf 'hello world' > /srv/testshare/alpha.txt
dd if=/dev/zero of=/srv/testshare/beta.bin bs=1024 count=1 2>/dev/null
mkdir -p /srv/testshare/subdir
printf 'nested' > /srv/testshare/subdir/nested.txt

# 600 entries under 42-character names. Both numbers are load-bearing and
# neither is arbitrary: the count is what invariant 1's end-to-end check
# asserts a listing returns, and the name length is what makes a 100-entry
# Samba reply large enough to need more than one message. With ordinary
# 8-character names the same 100 entries are about 11 KB and nothing splits.
mkdir -p /srv/testshare/bigdir
i=0
while [ "$i" -lt 600 ]; do
  printf 'x' > "$(printf '/srv/testshare/bigdir/fixture-entry-with-a-longish-name-%04d.dat' "$i")"
  i=$((i + 1))
done

# Listing an empty directory is a named live check in its own right: no
# committed fixture holds one, and the way to fail it is a one-line ordering
# mistake in the no-progress guard.
mkdir -p /srv/testshare/emptydir

chown -R smbtest:smbtest /srv/testshare

# Prove the seeding produced what the checks assume, rather than assuming it.
count=$(ls -1 /srv/testshare/bigdir | wc -l)
[ "$count" -eq 600 ] || { echo "seed: bigdir holds $count entries, expected 600" >&2; exit 1; }
name=$(ls -1 /srv/testshare/bigdir | head -1)
len=${#name}
[ "$len" -eq 42 ] || { echo "seed: entry name '$name' is $len characters, expected 42" >&2; exit 1; }
echo "seed: 600 entries under ${len}-character names, plus an empty directory"
