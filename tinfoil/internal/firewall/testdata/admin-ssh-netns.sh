#!/usr/bin/env bash
# Called only inside TestAdminSSHForwardedTraffic's private user/net namespace.
# Exercise the rendered guest policy with real TCP traffic and DNAT. This does
# not model the host forwarding service or replace real-CVM qualification.
set -euo pipefail
client_pid=""
server_pid=""
listener_pid=""
cleanup() {
  for pid in "$listener_pid" "$client_pid" "$server_pid"; do
    if test -n "$pid"; then kill "$pid" 2>/dev/null || true; fi
  done
  wait 2>/dev/null || true
}
trap cleanup EXIT
unshare --net sleep 30 &
client_pid=$!
unshare --net sleep 30 &
server_pid=$!
# Wait until both children have actually entered their new network namespaces.
for pid in "$client_pid" "$server_pid"; do
  for attempt in {1..100}; do
    if test "$(readlink /proc/"$pid"/ns/net)" != "$(readlink /proc/self/ns/net)"; then break; fi
    sleep .01
  done
done
ip link set lo up
ip link add external type veth peer name client
ip link set client netns "$client_pid"
ip address add 198.18.0.1/24 dev external
ip link set external up
nsenter -t "$client_pid" -n ip address add 198.18.0.2/24 dev client
nsenter -t "$client_pid" -n ip link set client up
nsenter -t "$client_pid" -n ip route add default via 198.18.0.1
ip link add name dev type bridge
ip address add 10.88.0.1/24 dev dev
ip link set dev dev up
ip link add workload type veth peer name server
ip link set workload master dev
ip link set workload up
ip link set server netns "$server_pid"
nsenter -t "$server_pid" -n ip address add 10.88.0.2/24 dev server
nsenter -t "$server_pid" -n ip link set server up
nsenter -t "$server_pid" -n ip link set lo up
nsenter -t "$server_pid" -n ip route add default via 10.88.0.1
sysctl -q -w net.ipv4.ip_forward=1
nsenter -t "$server_pid" -n python3 -u - <<'PY' &
import socket, threading
def serve(listener):
    while True:
        conn, _ = listener.accept()
        with conn:
            conn.sendall(conn.recv(64))
for port in (22, 3000):
    listener = socket.socket()
    listener.bind(('0.0.0.0', port))
    listener.listen()
    threading.Thread(target=serve, args=(listener,), daemon=True).start()
threading.Event().wait()
PY
listener_pid=$!
# Check listener readiness locally, before applying the forward policy.
nsenter -t "$server_pid" -n python3 - <<'PY'
import socket, time
for _ in range(100):
    try:
        with socket.create_connection(('127.0.0.1', 3000), timeout=.1):
            break
    except OSError:
        time.sleep(.01)
else:
    raise RuntimeError('listeners did not start')
PY
for policy in "$@"; do
  nft -f "$policy"
  nsenter -t "$client_pid" -n python3 - "$policy" <<'PY'
import socket, sys
admin = sys.argv[1].endswith('/admin.nft')
for host, port, allowed in [('198.18.0.1', 22, admin),
                            ('198.18.0.1', 3000, False),
                            ('10.88.0.2', 22, False)]:
    succeeded = False
    try:
        with socket.create_connection((host, port), timeout=.25) as conn:
            conn.sendall(b'reply-path')
            succeeded = conn.recv(64) == b'reply-path'
    except OSError:
        pass
    assert succeeded == allowed, (sys.argv[1], host, port, succeeded, allowed)
PY
done
