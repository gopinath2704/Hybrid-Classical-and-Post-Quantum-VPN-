#!/usr/bin/env bash
# Real networked connect-time benchmark for 1-RTT session resumption (v3-kem).
#
# Requires root, native liboqs, and a working Python environment.
# Creates namespace + veth + tc netem, starts the real VPN server with
# resumption enabled, then for each iteration measures two connect times:
#   full   = cold full handshake (resumption ticket removed first)
#   resume = 1-RTT resumption using the ticket saved by the full connect
# Timed from `vpn.cli client connect` to first successful ping of 10.8.0.1.
#
# Usage:
#   sudo eval/run_resumption_net.sh <profile> [--iterations N] [--out FILE]
#
# Profiles: lan, metro, continent, lossy-1, lossy-5, mtu-1280
set -euo pipefail

PROFILE=${1:?usage: run_resumption_net.sh <profile> [--iterations N] [--out FILE]}
shift
ITERATIONS=20
OUT=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --iterations) ITERATIONS=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUN_DIR=$(mktemp -d /tmp/pqvpn-resume.XXXXXX)
SERVER_NS=pqres-srv-$$
CLIENT_NS=pqres-cli-$$
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]:-}"; do wait "$pid" 2>/dev/null || true; done
  ip netns del "$SERVER_NS" 2>/dev/null || true
  ip netns del "$CLIENT_NS" 2>/dev/null || true
  [[ -n "${KEEP_RUN_DIR:-}" ]] || rm -rf "$RUN_DIR"
  [[ -n "${KEEP_RUN_DIR:-}" ]] && echo "KEPT: $RUN_DIR"
}
trap cleanup EXIT INT TERM

python3 -c "
import sys; sys.path.insert(0, '$ROOT_DIR')
from crypto.hybrid_crypto import get_crypto_status
s = get_crypto_status()
if s['pqc_mode'] != 'native_liboqs':
    print(f'FATAL: pqc_mode={s[\"pqc_mode\"]}; need native_liboqs', file=sys.stderr); sys.exit(1)
print(f'pqc_mode={s[\"pqc_mode\"]}')
"

declare -A RTT_MS LOSS_PCT LINK_MTU
RTT_MS=(  [lan]=0  [metro]=50  [continent]=200 [lossy-1]=50  [lossy-5]=50  [mtu-1280]=50 )
LOSS_PCT=([lan]=0  [metro]=0   [continent]=0   [lossy-1]=1   [lossy-5]=5   [mtu-1280]=0  )
LINK_MTU=([lan]=1500 [metro]=1500 [continent]=1500 [lossy-1]=1500 [lossy-5]=1500 [mtu-1280]=1280)

if [[ -z "${RTT_MS[$PROFILE]+x}" ]]; then
  echo "unknown profile: $PROFILE" >&2
  echo "available: ${!RTT_MS[*]}" >&2
  exit 1
fi
rtt=${RTT_MS[$PROFILE]}; loss=${LOSS_PCT[$PROFILE]}; mtu=${LINK_MTU[$PROFILE]}
delay_each=$(( rtt / 2 ))
echo "=== run_resumption_net: profile=$PROFILE rtt=${rtt}ms loss=${loss}% mtu=${mtu} iterations=${ITERATIONS} ==="

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

# --- Apply tc netem ---
if [[ "$delay_each" -gt 0 || "$loss" -gt 0 ]]; then
  netem_args="delay ${delay_each}ms"
  [[ "$loss" -gt 0 ]] && netem_args="$netem_args loss ${loss}%"
  ip netns exec "$SERVER_NS" tc qdisc add dev bench-s root netem $netem_args
  ip netns exec "$CLIENT_NS" tc qdisc add dev bench-c root netem $netem_args
fi

ip netns exec "$CLIENT_NS" ping -c 1 -W 3 192.0.2.1 >/dev/null

# --- Identities and v3-kem configs (resumption on by default) ---
mkdir -p "$RUN_DIR/server" "$RUN_DIR/client"
( cd "$ROOT_DIR"
  python -m vpn.cli identity generate \
    --private "$RUN_DIR/server/server.key" --public "$RUN_DIR/server/server.pub"
  python -m vpn.cli client-key generate --kem \
    --private "$RUN_DIR/client/client.key" --public "$RUN_DIR/client/client.pub"
  PUB_B64=$(base64 -w0 "$RUN_DIR/client/client.pub")
  python -m vpn.cli client authorize "$PUB_B64" \
    --database "$RUN_DIR/server/authorized.json" --client-id bench-client )
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
rekey_interval = 86400
protocol_version = 3
resumption_ticket_lifetime = 86400
outbound_interface = "bench-s"
dns_servers = []
server_identity_private_key = "server.key"
server_identity_public_key = "server.pub"
authorized_clients_file = "authorized.json"
connections_per_source = 100
cookie_mode = "off"
EOF

cat >"$RUN_DIR/client/client.toml" <<EOF
[client]
server_host = "192.0.2.1"
server_control_port = 51820
server_identity_fingerprint = "$FINGERPRINT"
server_identity_public_key = "../server/server.pub"
client_identity_private_key = "client.key"
client_identity_public_key = "client.pub"
protocol_version = 3
full_tunnel = false
dns_mode = "none"
dns_servers = []
tun_name = "pqbench0"
EOF

TICKET="$RUN_DIR/client/.pqvpn_ticket.json"

# --- Start server ---
ip netns exec "$SERVER_NS" sysctl -q -w net.ipv4.ip_forward=1
( cd "$ROOT_DIR"
  ip netns exec "$SERVER_NS" python -m vpn.cli server \
    --config "$RUN_DIR/server/server.toml" >"$RUN_DIR/server.log" 2>&1 ) &
PIDS+=("$!")
sleep 2
if ! kill -0 "${PIDS[0]}" 2>/dev/null; then
  echo "FATAL: server failed to start" >&2; cat "$RUN_DIR/server.log" >&2; exit 1
fi

CSV_FILE="${OUT:-$RUN_DIR/results.csv}"
echo "system,profile,metric,run,value,unit" > "$CSV_FILE"

# time one connect: $1=phase label. Echoes ms (or -1 on failure).
measure_connect() {
  local phase=$1 start end connected=0 attempt
  ip -n "$CLIENT_NS" link del pqbench0 2>/dev/null || true
  start=$(date +%s%N)
  ( cd "$ROOT_DIR"
    ip netns exec "$CLIENT_NS" python -m vpn.cli client connect \
      --config "$RUN_DIR/client/client.toml" >"$RUN_DIR/client-$phase.log" 2>&1 ) &
  local cpid=$!
  for attempt in $(seq 1 120); do
    if ip netns exec "$CLIENT_NS" ping -c1 -W1 10.8.0.1 >/dev/null 2>&1; then connected=1; break; fi
    sleep 0.05
  done
  end=$(date +%s%N)
  kill "$cpid" 2>/dev/null || true; wait "$cpid" 2>/dev/null || true
  if (( connected )); then echo $(( (end - start) / 1000000 )); else echo -1; fi
}

echo "Running $ITERATIONS full+resume connect measurements..."
for i in $(seq 0 $(( ITERATIONS - 1 ))); do
  # FULL: remove any ticket so the client performs a cold handshake
  rm -f "$TICKET"
  full_ms=$(measure_connect full)
  echo "pqvpn-net,$PROFILE,full_connect_ms,$i,$full_ms,ms" >> "$CSV_FILE"
  sleep 1
  # RESUME: the full connect above saved a ticket; reuse it (1-RTT)
  if [[ ! -f "$TICKET" ]]; then
    echo "  run $i: WARN no ticket saved; resumption not exercised" >&2
    echo "pqvpn-net,$PROFILE,resume_connect_ms,$i,-1,ms" >> "$CSV_FILE"
  else
    resume_ms=$(measure_connect resume)
    echo "pqvpn-net,$PROFILE,resume_connect_ms,$i,$resume_ms,ms" >> "$CSV_FILE"
  fi
  printf "  run %d: full=%s ms  resume=%s ms\n" "$i" "$full_ms" "${resume_ms:--}"
  sleep 1
done

echo "=== medians ==="
python3 -c "
import csv, statistics
rows=list(csv.DictReader(open('$CSV_FILE')))
for metric in ('full_connect_ms','resume_connect_ms'):
    vals=[int(r['value']) for r in rows if r['metric']==metric and int(r['value'])>=0]
    if vals: print(f'  {metric}: median={statistics.median(vals):.0f} ms  n={len(vals)}')
"
echo "CSV: $CSV_FILE"
