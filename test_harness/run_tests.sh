#!/bin/bash
# Runs INSIDE the privileged client container. SERVER is the samba host.
SERVER="${SERVER:-smbserver}"
AUTH=/harness/authfile.txt
PY="python3 /opt/mount_shares.py"

sep() { echo; echo "############################################################"; echo "# $*"; echo "############################################################"; }

sep "0. Wait for the SMB server to accept connections"
for i in $(seq 1 30); do
    if python3 - "$SERVER" <<'EOF'
import socket,sys
s=socket.socket(); s.settimeout(2)
try:
    s.connect((sys.argv[1],445)); print("port 445 open"); sys.exit(0)
except Exception as e:
    sys.exit(1)
EOF
    then break; fi
    sleep 1
done

sep "1. Show ALL shares (-show) — every share incl. no-access + IPC\$"
$PY -A "$AUTH" "$SERVER" -show

sep "2. List READABLE shares only (default) — 'secret' must NOT appear"
$PY -A "$AUTH" "$SERVER"

sep "3. MOUNT all readable shares (-m)"
$PY -A "$AUTH" "$SERVER" -m

sep "4. Prove files are actually visible under each mount"
echo ">> Local directory tree created by the tool:"
find SMBSERVER -maxdepth 2 -print 2>/dev/null | sort
echo
echo ">> Contents of each mounted share:"
find SMBSERVER -maxdepth 2 -name 'README_*' -print 2>/dev/null | sort | while read -r f; do
    echo "---- $f ----"
    cat "$f"
done
echo
echo ">> mount table (cifs entries):"
mount | grep cifs || echo "  (no cifs mounts!)"

sep "5. Re-run mount (-m) again — should say 'already exists', not double-mount"
$PY -A "$AUTH" "$SERVER" -m

sep "6. UNMOUNT everything (-u) and clean up dirs"
$PY -A "$AUTH" "$SERVER" -u
echo ">> Remaining cifs mounts after unmount:"
mount | grep cifs || echo "  (none — good)"
echo ">> Remaining local dirs:"
find SMBSERVER -maxdepth 2 -print 2>/dev/null | sort || echo "  (SMBSERVER dir gone — good)"

sep "7. Negative test: WRONG password must fail cleanly, mount nothing, leave no empty dirs"
printf 'username=testuser\npassword=WRONGPASSWORD\ndomain=WORKGROUP\n' > /tmp/badauth
$PY -A /tmp/badauth "$SERVER" -m
echo ">> cifs mounts after bad-cred mount attempt:"
mount | grep cifs || echo "  (none — good, no phantom mounts)"
echo ">> local dirs after bad-cred mount attempt:"
find SMBSERVER -maxdepth 2 -print 2>/dev/null | sort || echo "  (none — good, no empty dirs left behind)"

sep "DONE"
