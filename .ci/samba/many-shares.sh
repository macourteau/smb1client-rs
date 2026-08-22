#!/bin/sh
# Runs a second acceptance container carrying many shares, on port 10446.
#
# Not part of the acceptance gate: it exists because share enumeration has a
# failure mode no other server here reaches. RAP cannot carry a list this long,
# so the enumeration falls through to DCE/RPC and the reply arrives in hundreds
# of fragments — the multi-PDU assembly path, which every committed fixture
# answers in a single PDU. Bounding that assembly by a fragment count rather
# than by bytes made 2,000 shares fail outright, and this is what found it.
#
#   .ci/samba/many-shares.sh 2000
#   cargo run --example list_shares -- 127.0.0.1:10446 smbtest smbtest
#
# The acceptance container is left alone; this is a separate one from the same
# image. `docker rm -f smb1client-manyshares` when finished.
set -eu

count="${1:-2000}"
here="$(dirname "$0")"
conf="$(mktemp -t smb-manyshares)"

cat "$here/smb.conf" > "$conf"
i=0
while [ "$i" -lt "$count" ]; do
    printf '\n[share%04d]\n   path = /srv/testshare\n   read only = yes\n   guest ok = no\n   browseable = yes\n   comment = A share whose comment takes real room in the NDR stub, number %04d\n' "$i" "$i" >> "$conf"
    i=$((i + 1))
done

docker rm -f smb1client-manyshares >/dev/null 2>&1 || true
docker run -d --name smb1client-manyshares -p 10446:445 \
    -v "$conf":/etc/samba/smb.conf:ro smb1client-acceptance >/dev/null
sleep 5
# Seeded like the acceptance container, so that `assert-nt1.sh` proves NT1 the
# same way here — it checks for the seeded content rather than an exit status,
# smbclient exiting 0 even when protocol negotiation fails.
docker exec smb1client-manyshares /usr/local/bin/seed.sh >/dev/null
docker exec smb1client-manyshares /usr/local/bin/assert-nt1.sh >/dev/null
echo "smb1client-manyshares is serving $count shares on 127.0.0.1:10446"
