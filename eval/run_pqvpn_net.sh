#!/usr/bin/env bash
# Real networked PQVPN connect-time benchmark.
#
# Requires root, native liboqs, and a working Python environment.
# Creates namespace + veth + tc netem, starts the real VPN server, and
# measures time from `vpn.cli client connect` to first successful ping
# of 10.8.0.1 through the tunnel (pqvpn-net, cold: new process, no ticket).
# Then measures the same from an IPC CONNECT to an already-running
# `app.client --service` (pqvpn-net-warm, full handshake, no ticket).
#
# Usage:
#   sudo eval/run_pqvpn_net.sh <profile> [--iterations N] [--out FILE]
#
# Profiles: lan, metro, continent, lossy-1, lossy-5, mtu-1280
set -euo pipefail

PROFILE=${1:?usage: run_pqvpn_net.sh <profile> [--iterations N] [--out FILE]}
shift
ITERATIONS=30
OUT=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --iterations) ITERATIONS=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUN_DIR=$(mktemp -d /tmp/pqvpn-net.XXXXXX)
SERVER_NS=pqnet-srv-$$
CLIENT_NS=pqnet-cli-$$
PIDS=()

# --- Verify native PQC ---
python3 -c "
import sys; sys.path.insert(0, '$ROOT_DIR')
from crypto.hybrid_crypto import get_crypto_status
s = get_crypto_status()
if s['pqc_mode'] != 'native_liboqs':
    print(f'FATAL: pqc_mode={s[\"pqc_mode\"]}; need native_liboqs', file=sys.stderr)
    sys.exit(1)
print(f'pqc_mode={s[\"pqc_mode\"]}')
try:
    import oqs
    v = oqs.oqs_version() if hasattr(oqs, 'oqs_version') else 'unknown'
except Exception:
    v = 'unknown'
print(f'liboqs_version={v}')
"

# --- Profile parameters ---
declare -A RTT_MS LOSS_PCT LINK_MTU
RTT_MS=(  [lan]=0  [metro]=50  [continent]=200 [lossy-1]=50  [lossy-5]=50  [mtu-1280]=50 )
LOSS_PCT=([lan]=0  [metro]=0   [continent]=0   [lossy-1]=1   [lossy-5]=5   [mtu-1280]=0  )
LINK_MTU=([lan]=1500 [metro]=1500 [continent]=1500 [lossy-1]=1500 [lossy-5]=1500 [mtu-1280]=1280)

if [[ -z "${RTT_MS[$PROFILE]+x}" ]]; then
  echo "unknown profile: $PROFILE" >&2
  echo "available: ${!RTT_MS[*]}" >&2
  exit 1
fi

rtt=${RTT_MS[$PROFILE]}
loss=${LOSS_PCT[$PROFILE]}
mtu=${LINK_MTU[$PROFILE]}
delay_each=$(( rtt / 2 ))

cleanup() {
  # The service's tmpfs /run lives in its private mount namespace, so killing it leaves no mounts.
  [[ -s "$RUN_DIR/service.pid" ]] && PIDS+=("$(cat "$RUN_DIR/service.pid")")
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]:-}"; do wait "$pid" 2>/dev/null || true; done
  ip netns del "$SERVER_NS" 2>/dev/null || true
  ip netns del "$CLIENT_NS" 2>/dev/null || true
  rm -rf "$RUN_DIR"
}
trap cleanup EXIT INT TERM

echo "=== run_pqvpn_net: profile=$PROFILE  rtt=${rtt}ms  loss=${loss}%  mtu=${mtu}  iterations=${ITERATIONS} ==="

# --- Create namespaces and veth pair ---
ip netns add "$SERVER_NS"
ip netns add "$CLIENT_NS"
ip -n "$SERVER_NS" link set lo up
ip -n "$CLIENT_NS" link set lo up

ip link add bench-s type veth peer name bench-c
ip link set bench-s netns "$SERVER_NS"
ip link set bench-c netns "$CLIENT_NS"

ip -n "$SERVER_NS" addr add 192.0.2.1/24 dev bench-s
ip -n "$CLIENT_NS" addr add 192.0.2.2/24 dev bench-c
ip -n "$SERVER_NS" link set bench-s up mtu "$mtu"
ip -n "$CLIENT_NS" link set bench-c up mtu "$mtu"
#ip -n "$CLIENT_NS" route add default via 192.0.2.1

# --- Apply tc netem ---
if (( delay_each > 0 )) || (( loss > 0 )); then
  netem_args="delay ${delay_each}ms"
  if (( loss > 0 )); then
    netem_args="$netem_args loss ${loss}%"
  fi
  ip netns exec "$SERVER_NS" tc qdisc add dev bench-s root netem $netem_args
  ip netns exec "$CLIENT_NS" tc qdisc add dev bench-c root netem $netem_args
fi

# --- Verify connectivity ---
ip netns exec "$CLIENT_NS" ping -c 1 -W 3 192.0.2.1 >/dev/null

# --- Generate identities (no ALLOW_MOCK_PQC) ---
mkdir -p "$RUN_DIR/server" "$RUN_DIR/client"
cd "$ROOT_DIR"
python -m vpn.cli identity generate \
  --private "$RUN_DIR/server/server.key" --public "$RUN_DIR/server/server.pub"
python -m vpn.cli client-key generate \
  --private "$RUN_DIR/client/client.key" --public "$RUN_DIR/client/client.pub"
python -m vpn.cli client authorize \
  "$(base64 -w0 "$RUN_DIR/client/client.pub")" \
  --database "$RUN_DIR/server/authorized.json" --client-id bench-client
FINGERPRINT=$(sha256sum "$RUN_DIR/server/server.pub" | awk '{print $1}')

cat >"$RUN_DIR/server/server.toml" <<EOF
[server]
listen_host = "0.0.0.0"
control_port = 51820
udp_port = 51820
vpn_subnet = "10.8.0.0/24"
server_vpn_ip = "10.8.0.1"
max_clients = 4
handshake_timeout = 30
rekey_interval = 3600
outbound_interface = "bench-s"
dns_servers = []
server_identity_private_key = "server.key"
server_identity_public_key = "server.pub"
authorized_clients_file = "authorized.json"
connections_per_source = 100
EOF

cat >"$RUN_DIR/client/client.toml" <<EOF
[client]
server_host = "192.0.2.1"
server_control_port = 51820
server_identity_fingerprint = "$FINGERPRINT"
server_identity_public_key = "../server/server.pub"
client_identity_private_key = "client.key"
full_tunnel = false
dns_mode = "none"
dns_servers = []
tun_name = "pqbench0"
EOF

# --- Start server ---
ip netns exec "$SERVER_NS" sysctl -q -w net.ipv4.ip_forward=1
ip netns exec "$SERVER_NS" \
  python -m vpn.cli server --config "$RUN_DIR/server/server.toml" \
  >"$RUN_DIR/server.log" 2>&1 &
PIDS+=("$!")
sleep 2

if ! kill -0 "${PIDS[0]}" 2>/dev/null; then
  echo "FATAL: server failed to start" >&2
  cat "$RUN_DIR/server.log" >&2
  exit 1
fi

# --- CSV output ---
CSV_FILE="${OUT:-$RUN_DIR/results.csv}"
echo "system,profile,metric,run,value,unit" > "$CSV_FILE"

TICKET="$RUN_DIR/client/.pqvpn_ticket.json"

record() {  # $1=system $2=run $3=start_ns $4=connected
  local ms=-1
  if (( $4 )) && [[ -n "$3" ]]; then ms=$(( ($(date +%s%N) - $3) / 1000000 )); fi
  echo "$1,$PROFILE,connect_time_ms,$2,$ms,ms" >> "$CSV_FILE"
  printf "  %s run %d: %s ms\n" "$1" "$2" "$ms"
}

# Poll every 10 ms (50 ms before Phase 1) so warm connects near 40 ms are resolvable.
wait_tunnel() {
  local attempt
  for attempt in $(seq 1 300); do
    ip netns exec "$CLIENT_NS" ping -c1 -W1 10.8.0.1 >/dev/null 2>&1 && return 0
    sleep 0.01
  done
  return 1
}

# --- Cold: new client process per connect ---
echo "Running $ITERATIONS cold connect-time measurements..."
for i in $(seq 0 $(( ITERATIONS - 1 ))); do
  START_NS=$(date +%s%N)

  # Ensure stale TUN device is gone; drop the ticket so every run is a full handshake
  ip -n "$CLIENT_NS" link del pqbench0 2>/dev/null || true
  rm -f "$TICKET"

  ip netns exec "$CLIENT_NS" \
    python -m vpn.cli client connect --config "$RUN_DIR/client/client.toml" \
    >"$RUN_DIR/client.log" 2>&1 &
  CLIENT_PID=$!

  CONNECTED=0
  wait_tunnel && CONNECTED=1
  record pqvpn-net "$i" "$START_NS" "$CONNECTED"

  # Disconnect client
  kill "$CLIENT_PID" 2>/dev/null || true
  wait "$CLIENT_PID" 2>/dev/null || true
  sleep 2
done

# --- Warm: CONNECT over the IPC of an already-running client service ---
# Private mount namespace + tmpfs /run: the production socket path /run/pqvpn/client.sock,
# its mode and the SO_PEERCRED check are unchanged, without colliding with a host service.
ip -n "$CLIENT_NS" link del pqbench0 2>/dev/null || true
ip netns exec "$CLIENT_NS" unshare -m --propagation private sh -c \
  'mount -t tmpfs -o mode=0755 tmpfs /run && mkdir /run/pqvpn && echo $$ > "$1" &&
   exec python -m app.client --service --config "$2"' \
  sh "$RUN_DIR/service.pid" "$RUN_DIR/client/client.toml" >"$RUN_DIR/service.log" 2>&1 &
PIDS+=("$!")

# ipc COMMAND: prints wall-clock ns just before sending (so START excludes Python startup,
# as for an already-open GUI); exits non-zero on an error reply.
ipc() {
  nsenter -t "$(cat "$RUN_DIR/service.pid")" -m python -c '
import sys, socket, time; sys.path.insert(0, sys.argv[1])
from app.client import _socket_path, ipc_send, ipc_recv
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM); s.connect(str(_socket_path()))
print(time.time_ns(), flush=True); ipc_send(s, {"command": sys.argv[2]})
reply = ipc_recv(s, 60); print(reply, file=sys.stderr); sys.exit("error" in reply)' "$ROOT_DIR" "$1"
}

for attempt in $(seq 1 100); do
  [[ -s "$RUN_DIR/service.pid" ]] && nsenter -t "$(cat "$RUN_DIR/service.pid")" -m test -S /run/pqvpn/client.sock && break
  sleep 0.1
done
if ! nsenter -t "$(cat "$RUN_DIR/service.pid")" -m test -S /run/pqvpn/client.sock; then
  echo "FATAL: client service failed to start" >&2
  cat "$RUN_DIR/service.log" >&2
  exit 1
fi

# Untimed warm-up: the service imports vpn.runtime lazily on its first CONNECT.
rm -f "$TICKET"
ipc CONNECT >/dev/null 2>>"$RUN_DIR/ipc.log" && wait_tunnel
ipc DISCONNECT >/dev/null 2>>"$RUN_DIR/ipc.log" || true
sleep 2

echo "Running $ITERATIONS warm connect-time measurements..."
for i in $(seq 0 $(( ITERATIONS - 1 ))); do
  rm -f "$TICKET"
  ipc CONNECT >"$RUN_DIR/ipc.start" 2>>"$RUN_DIR/ipc.log" &
  IPC_PID=$!
  CONNECTED=0
  wait_tunnel && CONNECTED=1
  START_NS=$(head -n1 "$RUN_DIR/ipc.start")
  record pqvpn-net-warm "$i" "$START_NS" "$CONNECTED"
  wait "$IPC_PID" 2>/dev/null || true
  ipc DISCONNECT >/dev/null 2>>"$RUN_DIR/ipc.log" || true
  sleep 2
done

echo "=== run_pqvpn_net: completed profile=$PROFILE ==="
echo "Results: $CSV_FILE"
cat "$CSV_FILE"
