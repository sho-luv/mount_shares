#!/bin/bash
set -e

# Password deliberately full of shell-significant characters: space, ! @ #
# This is the credential the client will authenticate + mount with.
PW='Pa,ss w0rd!@#x'

# Create share directories and drop a marker file in each so we can prove
# that files are actually visible after a successful mount.
for d in public readonly shared_folder rnd apostrophe dollar deep_space secret dropbox; do
    mkdir -p "/srv/shares/$d"
    echo "This is the $d share. flag=FLAG_${d}_$(printf 'OK')" > "/srv/shares/$d/README_${d}.txt"
    chmod -R 0777 "/srv/shares/$d"
done

# Users (no shell, no home).
useradd -M -s /usr/sbin/nologin testuser  2>/dev/null || true
useradd -M -s /usr/sbin/nologin otheruser 2>/dev/null || true

# Set Samba passwords non-interactively.
printf '%s\n%s\n' "$PW" "$PW"             | smbpasswd -s -a testuser
printf '%s\n%s\n' "otherpass" "otherpass" | smbpasswd -s -a otheruser

echo "==== Samba test server ready. Shares configured: ===="
testparm -s 2>/dev/null | grep '^\[' || true

exec smbd --foreground --no-process-group --debuglevel=1
