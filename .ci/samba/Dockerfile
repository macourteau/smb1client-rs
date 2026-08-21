# The acceptance oracle. Pinned deliberately, and excluded from dependency
# automation in .github/dependabot.yml — see README.md in this directory for
# why an automated bump here would delete the gate rather than fail it.
#
# Alpine keeps SMB1 (NT1) server support compiled into its samba package; some
# distributions build with --without-smb1-server, and upstream is actively
# removing SMB1 server support.
FROM alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b

# samba-client provides smbclient, which the healthcheck uses to prove the
# server still answers NT1 rather than merely being up.
RUN apk add --no-cache samba=4.23.8-r0 samba-client=4.23.8-r0

RUN adduser -D -H -s /sbin/nologin smbtest \
    && printf 'smbtest\nsmbtest\n' | smbpasswd -a -s smbtest \
    && mkdir -p /srv/testshare \
    && chown smbtest:smbtest /srv/testshare

COPY smb.conf /etc/samba/smb.conf
COPY seed.sh assert-nt1.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/seed.sh /usr/local/bin/assert-nt1.sh

EXPOSE 445

CMD ["smbd", "--foreground", "--no-process-group", "--debug-stdout"]
