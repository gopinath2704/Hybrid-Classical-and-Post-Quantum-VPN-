#!/usr/bin/env bash
# Namespace-based benchmark harness with tc netem network emulation.
#
# Usage (requires root):
#   bash scripts/bench_netem.sh <profile> [--iterations N]
#
# Profiles are defined in benchmarks.py NETEM_PROFILES.
# This script creates isolated namespaces, applies tc netem rules,
# starts a VPN server, and measures real handshake latency through
# the emulated network.
set -euo pipefail

PROFILE=${1:?usage: bench_netem.sh <profile> [--iterations N]}
shift
ITERATIONS=50
while [[ $# -gt 0 ]]; do
  case $1 in
    --iterations) ITERATIONS=$2; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUN_DIR=$(mktemp -d /tmp/pqvpn-bench.XXXXXX)
SERVER_NS=bench-srv-$$
CLIENT_NS=bench-cli-$$
PIDS=()

# Map profile names to netem parameters.
declare -A RTT_MS LOSS_PCT LINK_MTU
RTT_MS=(  [lan]=0  [metro]=50  [continent]=200 [lossy-1]=50  [lossy-5]=50  [mtu-1280]=50  [mtu-1400]=50  [worst]=200 )
LOSS_PCT=([lan]=0  [metro]=0   [continent]=0   [lossy-1]=1   [lossy-5]=5   [mtu-1280]=0   [mtu-1400]=0   [worst]=5   )
LINK_MTU=([lan]=1500 [metro]=1500 [continent]=1500 [lossy-1]=1500 [lossy-5]=1500 [mtu-1280]=1280 [mtu-1400]=1400 [worst]=1280)

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
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]:-}"; do wait "$pid" 2>/dev/null || true; done
  ip netns del "$SERVER_NS" 2>/dev/null || true
  ip netns del "$CLIENT_NS" 2>/dev/null || true
  rm -rf "$RUN_DIR"
}
trap cleanup EXIT INT TERM

echo "=== bench_netem: profile=$PROFILE  rtt=${rtt}ms  loss=${loss}%  mtu=${mtu} ==="

# Create namespaces and veth pair.
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
ip -n "$CLIENT_NS" route add default via 192.0.2.1

# Apply tc netem on both ends (half the delay on each side).
if (( delay_each > 0 )) || (( loss > 0 )); then
  netem_args="delay ${delay_each}ms"
  if (( loss > 0 )); then
    netem_args="$netem_args loss ${loss}%"
  fi
  ip netns exec "$SERVER_NS" tc qdisc add dev bench-s root netem $netem_args
  ip netns exec "$CLIENT_NS" tc qdisc add dev bench-c root netem $netem_args
fi

# Verify connectivity.
ip netns exec "$CLIENT_NS" ping -c 1 -W 3 192.0.2.1 >/dev/null

# Generate identities.
mkdir -p "$RUN_DIR/server" "$RUN_DIR/client"
cd "$ROOT_DIR"
ALLOW_MOCK_PQC=1 python -m vpn.cli identity generate \
  --private "$RUN_DIR/server/server.key" --public "$RUN_DIR/server/server.pub"
ALLOW_MOCK_PQC=1 python -m vpn.cli client-key generate \
  --private "$RUN_DIR/client/client.key" --public "$RUN_DIR/client/client.pub"
ALLOW_MOCK_PQC=1 python -m vpn.cli client authorize \
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

# Start server in server namespace.
ip netns exec "$SERVER_NS" sysctl -q -w net.ipv4.ip_forward=1
ALLOW_MOCK_PQC=1 ip netns exec "$SERVER_NS" \
  python -m vpn.cli server --config "$RUN_DIR/server/server.toml" --allow-mock-pqc \
  >"$RUN_DIR/server.log" 2>&1 &
PIDS+=("$!")
sleep 2

# Run benchmarks from client namespace.
echo "Running benchmarks with $ITERATIONS iterations under profile $PROFILE..."
ALLOW_MOCK_PQC=1 ip netns exec "$CLIENT_NS" \
  python -m benchmarks --all --iterations "$ITERATIONS" --profile "$PROFILE"

echo "=== bench_netem: completed profile=$PROFILE ==="
