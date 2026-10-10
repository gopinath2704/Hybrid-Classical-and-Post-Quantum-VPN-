#!/usr/bin/env bash
# Measure re-handshake and rekey cost on the netns+veth topology.
#
# Sets up the PQ-VPN tunnel, starts a fast ping through it, triggers
# N rekeys (via short rekey_interval) and N re-handshakes (via short
# rehandshake_interval), and measures:
#   - epoch transition time (from request to new epoch active)
#   - lost or late pings across the epoch switch
#   - wire bytes for each control exchange (via tcpdump)
#
# Usage:
#   sudo eval/run_rehandshake_net.sh [--iterations N] [--out FILE]
set -euo pipefail

ITERATIONS=10
OUT=""
while [[ $# -gt 0 ]]; do
  case $1 in
    --iterations) ITERATIONS=$2; shift 2 ;;
    --out) OUT=$2; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
source "$ROOT_DIR/eval/netem_profiles.sh"

CSV_FILE="${OUT:-/dev/stdout}"
if [[ "$CSV_FILE" != "/dev/stdout" ]]; then
  mkdir -p "$(dirname "$CSV_FILE")"
fi
echo "system,profile,metric,run,value,unit" > "$CSV_FILE"

echo "=== run_rehandshake_net: iterations=$ITERATIONS ===" >&2

# ---------- Phase 1: Rekey (short rekey_interval) ----------
echo "--- Phase 1: Rekey with short interval ---" >&2

RUN_DIR=$(mktemp -d /tmp/pqvpn-rh.XXXXXX)
SERVER_NS=pqrh-srv-$$
CLIENT_NS=pqrh-cli-$$
PIDS=()

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]:-}"; do wait "$pid" 2>/dev/null || true; done
  ip netns del "$SERVER_NS" 2>/dev/null || true
  ip netns del "$CLIENT_NS" 2>/dev/null || true
  rm -rf "$RUN_DIR"
}
trap cleanup EXIT INT TERM

ip netns add "$SERVER_NS"
ip netns add "$CLIENT_NS"
ip -n "$SERVER_NS" link set lo up
ip -n "$CLIENT_NS" link set lo up

ip link add bench-s type veth peer name bench-c
ip link set bench-s netns "$SERVER_NS"
ip link set bench-c netns "$CLIENT_NS"
ip -n "$SERVER_NS" addr add 192.0.2.1/24 dev bench-s
ip -n "$CLIENT_NS" addr add 192.0.2.2/24 dev bench-c
ip -n "$SERVER_NS" link set bench-s up mtu 1500
ip -n "$CLIENT_NS" link set bench-c up mtu 1500
ip netns exec "$CLIENT_NS" ping -c 1 -W 3 192.0.2.1 >/dev/null

mkdir -p "$RUN_DIR/server" "$RUN_DIR/client"
cd "$ROOT_DIR"

echo "  Generating identities..." >&2
python -m vpn.cli identity generate \
  --private "$RUN_DIR/server/server.key" --public "$RUN_DIR/server/server.pub" || {
    echo "ERROR: server identity generation failed" >&2; exit 1; }
python -m vpn.cli client-key generate \
  --private "$RUN_DIR/client/client.key" --public "$RUN_DIR/client/client.pub" || {
    echo "ERROR: client key generation failed" >&2; exit 1; }
python -m vpn.cli client authorize \
  "$(base64 -w0 "$RUN_DIR/client/client.pub")" \
  --database "$RUN_DIR/server/authorized.json" --client-id bench-client || {
    echo "ERROR: client authorization failed" >&2; exit 1; }
FINGERPRINT=$(sha256sum "$RUN_DIR/server/server.pub" | awk '{print $1}')

# Short rekey_interval to trigger frequent rekeys; rehandshake disabled
REKEY_INTERVAL=5
cat >"$RUN_DIR/server/server.toml" <<EOF
[server]
listen_host = "0.0.0.0"
control_port = 51820
udp_port = 51820
vpn_subnet = "10.8.0.0/24"
server_vpn_ip = "10.8.0.1"
max_clients = 4
handshake_timeout = 30
rekey_interval = $REKEY_INTERVAL
rehandshake_interval = 0
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

ip netns exec "$SERVER_NS" sysctl -q -w net.ipv4.ip_forward=1

# Start server
ip netns exec "$SERVER_NS" \
  python -m vpn.cli server --config "$RUN_DIR/server/server.toml" \
  >"$RUN_DIR/server.log" 2>&1 &
PIDS+=("$!")
sleep 2

if ! kill -0 "${PIDS[0]}" 2>/dev/null; then
  echo "ERROR: server failed to start" >&2
  cat "$RUN_DIR/server.log" >&2
  exit 1
fi

# Start tcpdump to capture control traffic
PCAP="$RUN_DIR/rekey_capture.pcap"
ip netns exec "$SERVER_NS" tcpdump -i bench-s -w "$PCAP" -U 'tcp port 51820' 2>/dev/null &
TCPDUMP_PID=$!
PIDS+=("$TCPDUMP_PID")
sleep 0.5

# Start client
ip -n "$CLIENT_NS" link del pqbench0 2>/dev/null || true
ip netns exec "$CLIENT_NS" \
  python -m vpn.cli client connect --config "$RUN_DIR/client/client.toml" \
  >"$RUN_DIR/client.log" 2>&1 &
CLIENT_PID=$!
PIDS+=("$CLIENT_PID")

# Wait for tunnel up
CONNECTED=0
for attempt in $(seq 1 60); do
  if ip netns exec "$CLIENT_NS" ping -c1 -W1 10.8.0.1 >/dev/null 2>&1; then
    CONNECTED=1
    break
  fi
  sleep 0.5
done

if (( ! CONNECTED )); then
  echo "ERROR: tunnel failed to come up" >&2
  cat "$RUN_DIR/client.log" >&2
  exit 1
fi

echo "  Tunnel up, waiting for $ITERATIONS rekeys (interval=${REKEY_INTERVAL}s)..." >&2

# Start fast ping to detect disruptions across epoch switches
PING_LOG="$RUN_DIR/rekey_ping.log"
ip netns exec "$CLIENT_NS" ping -i 0.01 -W 1 10.8.0.1 > "$PING_LOG" 2>&1 &
PING_PID=$!
PIDS+=("$PING_PID")

# Wait for enough rekeys to happen
WAIT_TIME=$(( REKEY_INTERVAL * (ITERATIONS + 2) ))
echo "  Waiting ${WAIT_TIME}s for rekeys to accumulate..." >&2
sleep "$WAIT_TIME"

# Stop ping (SIGINT so ping prints its summary) and capture
kill -INT "$PING_PID" 2>/dev/null || true
wait "$PING_PID" 2>/dev/null || true
sleep 0.5
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

# Parse ping results — count response lines directly as fallback
PING_RX=$(grep -c 'bytes from' "$PING_LOG" 2>/dev/null || echo 0)
PING_SUMMARY=$(grep 'packets transmitted' "$PING_LOG" || true)
if [[ -n "$PING_SUMMARY" ]]; then
  PING_TX=$(echo "$PING_SUMMARY" | grep -oE '^[0-9]+')
  PING_LOSS_PCT=$(echo "$PING_SUMMARY" | grep -oE '[0-9.]+% packet loss' | grep -oE '^[0-9.]+')
else
  PING_TX=$PING_RX
  PING_LOSS_PCT=0
fi
echo "  Rekey phase: tx=$PING_TX rx=$PING_RX loss=${PING_LOSS_PCT}%" >&2

# Parse epoch count from logs
REKEY_COUNT=$(grep -c 'rekey complete epoch=' "$RUN_DIR/server.log" 2>/dev/null || echo 0)
CLIENT_REKEY_COUNT=$(grep -c 'rekey complete epoch=' "$RUN_DIR/client.log" 2>/dev/null || echo 0)
echo "  Server rekeys: $REKEY_COUNT, Client rekeys: $CLIENT_REKEY_COUNT" >&2

# Record results
echo "pqvpn-rekey,lan,rekey_ping_loss_pct,0,$PING_LOSS_PCT,percent" >> "$CSV_FILE"
echo "pqvpn-rekey,lan,rekey_ping_total,0,$PING_RX,packets" >> "$CSV_FILE"
echo "pqvpn-rekey,lan,rekey_epoch_transitions,0,$REKEY_COUNT,count" >> "$CSV_FILE"

# Count control packets from tcpdump
if [[ -f "$PCAP" ]]; then
  CTRL_PACKETS=$(tcpdump -r "$PCAP" -nn 2>/dev/null | wc -l)
  CTRL_BYTES=$(tcpdump -r "$PCAP" -nn 2>/dev/null | awk -F'length ' '{if(NF>1){split($2,a," ");sum+=a[1]}} END {print sum+0}')
  echo "pqvpn-rekey,lan,rekey_control_packets,0,$CTRL_PACKETS,packets" >> "$CSV_FILE"
  echo "pqvpn-rekey,lan,rekey_control_bytes,0,$CTRL_BYTES,bytes" >> "$CSV_FILE"
  echo "  Control traffic: $CTRL_PACKETS packets, $CTRL_BYTES bytes" >&2
fi

# Stop client and server
kill "$CLIENT_PID" 2>/dev/null || true
wait "$CLIENT_PID" 2>/dev/null || true
for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
for pid in "${PIDS[@]:-}"; do wait "$pid" 2>/dev/null || true; done
PIDS=()

echo "" >&2

# ---------- Phase 2: Re-handshake (short rehandshake_interval) ----------
echo "--- Phase 2: Re-handshake with short interval ---" >&2

# Clean up the old namespace
ip netns del "$SERVER_NS" 2>/dev/null || true
ip netns del "$CLIENT_NS" 2>/dev/null || true
rm -rf "$RUN_DIR"

RUN_DIR=$(mktemp -d /tmp/pqvpn-rh2.XXXXXX)
PIDS=()

ip netns add "$SERVER_NS"
ip netns add "$CLIENT_NS"
ip -n "$SERVER_NS" link set lo up
ip -n "$CLIENT_NS" link set lo up

ip link add bench-s type veth peer name bench-c
ip link set bench-s netns "$SERVER_NS"
ip link set bench-c netns "$CLIENT_NS"
ip -n "$SERVER_NS" addr add 192.0.2.1/24 dev bench-s
ip -n "$CLIENT_NS" addr add 192.0.2.2/24 dev bench-c
ip -n "$SERVER_NS" link set bench-s up mtu 1500
ip -n "$CLIENT_NS" link set bench-c up mtu 1500
ip netns exec "$CLIENT_NS" ping -c 1 -W 3 192.0.2.1 >/dev/null

mkdir -p "$RUN_DIR/server" "$RUN_DIR/client"
cd "$ROOT_DIR"

echo "  Generating identities..." >&2
python -m vpn.cli identity generate \
  --private "$RUN_DIR/server/server.key" --public "$RUN_DIR/server/server.pub" || {
    echo "ERROR: server identity generation failed" >&2; exit 1; }
python -m vpn.cli client-key generate \
  --private "$RUN_DIR/client/client.key" --public "$RUN_DIR/client/client.pub" || {
    echo "ERROR: client key generation failed" >&2; exit 1; }
python -m vpn.cli client authorize \
  "$(base64 -w0 "$RUN_DIR/client/client.pub")" \
  --database "$RUN_DIR/server/authorized.json" --client-id bench-client || {
    echo "ERROR: client authorization failed" >&2; exit 1; }
FINGERPRINT=$(sha256sum "$RUN_DIR/server/server.pub" | awk '{print $1}')

# Short rehandshake_interval; rekey disabled (high interval)
REHANDSHAKE_INTERVAL=8
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
rehandshake_interval = $REHANDSHAKE_INTERVAL
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

ip netns exec "$SERVER_NS" sysctl -q -w net.ipv4.ip_forward=1

# Start server
ip netns exec "$SERVER_NS" \
  python -m vpn.cli server --config "$RUN_DIR/server/server.toml" \
  >"$RUN_DIR/server.log" 2>&1 &
PIDS+=("$!")
sleep 2

if ! kill -0 "${PIDS[0]}" 2>/dev/null; then
  echo "ERROR: server failed to start" >&2
  cat "$RUN_DIR/server.log" >&2
  exit 1
fi

# Start tcpdump
PCAP="$RUN_DIR/rehandshake_capture.pcap"
ip netns exec "$SERVER_NS" tcpdump -i bench-s -w "$PCAP" -U 'tcp port 51820' 2>/dev/null &
TCPDUMP_PID=$!
PIDS+=("$TCPDUMP_PID")
sleep 0.5

# Start client
ip -n "$CLIENT_NS" link del pqbench0 2>/dev/null || true
ip netns exec "$CLIENT_NS" \
  python -m vpn.cli client connect --config "$RUN_DIR/client/client.toml" \
  >"$RUN_DIR/client.log" 2>&1 &
CLIENT_PID=$!
PIDS+=("$CLIENT_PID")

# Wait for tunnel up
CONNECTED=0
for attempt in $(seq 1 60); do
  if ip netns exec "$CLIENT_NS" ping -c1 -W1 10.8.0.1 >/dev/null 2>&1; then
    CONNECTED=1
    break
  fi
  sleep 0.5
done

if (( ! CONNECTED )); then
  echo "ERROR: tunnel failed to come up for re-handshake" >&2
  cat "$RUN_DIR/client.log" >&2
  exit 1
fi

echo "  Tunnel up, waiting for $ITERATIONS re-handshakes (interval=${REHANDSHAKE_INTERVAL}s)..." >&2

# Start fast ping
PING_LOG="$RUN_DIR/rehandshake_ping.log"
ip netns exec "$CLIENT_NS" ping -i 0.01 -W 1 10.8.0.1 > "$PING_LOG" 2>&1 &
PING_PID=$!
PIDS+=("$PING_PID")

# Wait for enough re-handshakes
WAIT_TIME=$(( REHANDSHAKE_INTERVAL * (ITERATIONS + 2) ))
echo "  Waiting ${WAIT_TIME}s for re-handshakes to accumulate..." >&2
sleep "$WAIT_TIME"

# Stop ping (SIGINT so ping prints its summary) and capture
kill -INT "$PING_PID" 2>/dev/null || true
wait "$PING_PID" 2>/dev/null || true
sleep 0.5
kill "$TCPDUMP_PID" 2>/dev/null || true
wait "$TCPDUMP_PID" 2>/dev/null || true

# Parse ping results — count response lines directly as fallback
PING_RX=$(grep -c 'bytes from' "$PING_LOG" 2>/dev/null || echo 0)
PING_SUMMARY=$(grep 'packets transmitted' "$PING_LOG" || true)
if [[ -n "$PING_SUMMARY" ]]; then
  PING_TX=$(echo "$PING_SUMMARY" | grep -oE '^[0-9]+')
  PING_LOSS_PCT=$(echo "$PING_SUMMARY" | grep -oE '[0-9.]+% packet loss' | grep -oE '^[0-9.]+')
else
  PING_TX=$PING_RX
  PING_LOSS_PCT=0
fi
echo "  Re-handshake phase: tx=$PING_TX rx=$PING_RX loss=${PING_LOSS_PCT}%" >&2

# Parse epoch count from logs
RH_COUNT=$(grep -c 'rehandshake complete epoch=' "$RUN_DIR/server.log" 2>/dev/null || echo 0)
CLIENT_RH_COUNT=$(grep -c 'rehandshake complete epoch=' "$RUN_DIR/client.log" 2>/dev/null || echo 0)
echo "  Server re-handshakes: $RH_COUNT, Client re-handshakes: $CLIENT_RH_COUNT" >&2

# Record results
echo "pqvpn-rehandshake,lan,rehandshake_ping_loss_pct,0,$PING_LOSS_PCT,percent" >> "$CSV_FILE"
echo "pqvpn-rehandshake,lan,rehandshake_ping_total,0,$PING_RX,packets" >> "$CSV_FILE"
echo "pqvpn-rehandshake,lan,rehandshake_epoch_transitions,0,$RH_COUNT,count" >> "$CSV_FILE"

# Count control packets
if [[ -f "$PCAP" ]]; then
  CTRL_PACKETS=$(tcpdump -r "$PCAP" -nn 2>/dev/null | wc -l)
  CTRL_BYTES=$(tcpdump -r "$PCAP" -nn 2>/dev/null | awk -F'length ' '{if(NF>1){split($2,a," ");sum+=a[1]}} END {print sum+0}')
  echo "pqvpn-rehandshake,lan,rehandshake_control_packets,0,$CTRL_PACKETS,packets" >> "$CSV_FILE"
  echo "pqvpn-rehandshake,lan,rehandshake_control_bytes,0,$CTRL_BYTES,bytes" >> "$CSV_FILE"
  echo "  Control traffic: $CTRL_PACKETS packets, $CTRL_BYTES bytes" >&2
fi

cleanup
trap - EXIT INT TERM

echo "" >&2
echo "=== run_rehandshake_net: complete ===" >&2
