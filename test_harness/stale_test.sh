#!/bin/bash
# Faithfully reproduces the FORENSICS-STORA stale-mount bug:
#   - mount shares against server at IP .10
#   - destroy that server (IP .10 gone for good -> mounts can never reconnect)
#   - bring up a replacement server (same hostname) at IP .11
#   - now the hostname still enumerates fine, but the old mountpoints are stale:
#     os.path.exists() on them lies/hangs, exactly like the real box.
set -e
sep() { echo; echo "############################################################"; echo "# $*"; echo "############################################################"; }
HARNESS=/Users/sho_luv/home/projects/mine/mount_shares/test_harness
NET=smbnet_static
CLIENT=msclient_stale

cleanup() {
  docker rm -f "$CLIENT" smbserver >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
cleanup
docker network create --subnet 172.30.0.0/16 "$NET" >/dev/null

start_server() { # $1 = ip
  docker run -d --name smbserver --network "$NET" --ip "$1" --hostname SMBSERVER mssamba >/dev/null
  for i in $(seq 1 30); do
    docker run --rm --network "$NET" msclient python3 - "$1" <<'EOF' 2>/dev/null && return 0
import socket,sys
s=socket.socket(); s.settimeout(2)
try: s.connect((sys.argv[1],445)); sys.exit(0)
except Exception: sys.exit(1)
EOF
    sleep 1
  done
}

sep "Boot server #1 at 172.30.0.10 and mount everything"
start_server 172.30.0.10
docker run -d --name "$CLIENT" --network "$NET" --privileged -v "$HARNESS":/harness msclient sleep infinity >/dev/null
docker exec "$CLIENT" python3 /opt/mount_shares.py -A /harness/authfile.txt smbserver -m 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g' | grep -E 'Mounted|Unable'
docker exec "$CLIENT" bash -c "mount | grep -c cifs | xargs echo 'live cifs mounts:'"

sep "Destroy server #1, boot replacement #2 at 172.30.0.11 (same hostname)"
docker rm -f smbserver >/dev/null
start_server 172.30.0.11
echo "replacement server up at .11; hostname 'smbserver' now resolves to:"
docker exec "$CLIENT" getent hosts smbserver

sep "Prove the bug: parent listing still sees the dirs, but stat() on the stale mountpoint fails"
docker exec "$CLIENT" bash -c "echo 'ls SMBSERVER ->'; ls SMBSERVER"
docker exec "$CLIENT" bash -c "python3 -c \"import os; print('parent listing sees public ->', 'public' in os.listdir('SMBSERVER'))\""
echo -n "os.path.exists(SMBSERVER/public) (10s guard) -> "
docker exec "$CLIENT" bash -c "timeout 10 python3 -c \"import os; print(os.path.exists('SMBSERVER/public'))\"" || echo "(stat HUNG/failed on the stale mount — the old check would strand it)"

sep "Run the FIXED -u against the stale mounts"
docker exec "$CLIENT" python3 /opt/mount_shares.py -A /harness/authfile.txt smbserver -u 2>&1 | sed -E 's/\x1b\[[0-9;]*m//g' | grep -E 'Unmounted|Can.t unmount|Unable'

sep "Verify: no stale cifs mounts, no leftover directories"
docker exec "$CLIENT" bash -c "mount | grep cifs || echo '  (no cifs mounts — good)'"
docker exec "$CLIENT" bash -c "ls SMBSERVER 2>&1 || echo '  (SMBSERVER dir gone — good)'"

cleanup
sep "STALE TEST DONE"
