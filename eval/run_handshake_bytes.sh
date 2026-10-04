#!/usr/bin/env bash
# Capture on-the-wire handshake bytes via tcpdump for PQ-VPN and WireGuard.
#
# Uses the same netns+veth topology as the M1 runners so byte counts are
# directly comparable. Captures ALL packets on the veth up to the first
# successful ping (= handshake complete), then reports total bytes and
# packet count. Runs N iterations per system on the lan profile (bytes
# are RTT-independent).
#
# Outputs CSV: system,profile,metric,run,value,unit
#
# Usage:
#   sudo eval/run_handshake_bytes.sh [--iterations N] [--out FILE]
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

if ! command -v tcpdump &>/dev/null; then
  echo "ERROR: tcpdump not found" >&2; exit 1
fi
if ! command -v wg &>/dev/null; then
  echo "WARNING: wg not found — WireGuard measurements will be skipped" >&2
  HAS_WG=0
else
  HAS_WG=1
fi

CSV_FILE="${OUT:-/dev/stdout}"
if [[ "$CSV_FILE" != "/dev/stdout" ]]; then
  mkdir -p "$(dirname "$CSV_FILE")"
fi
echo "system,profile,metric,run,value,unit" > "$CSV_FILE"

echo "=== run_handshake_bytes: iterations=$ITERATIONS ===" >&2

# ---------- PQ-VPN ----------
echo "--- PQ-VPN handshake bytes ---" >&2

python3 -c "
import sys; sys.path.insert(0, '$ROOT_DIR')
from crypto.hybrid_crypto import get_crypto_status
s = get_crypto_status()
if s['pqc_mode'] != 'native_liboqs':
    print(f'FATAL: pqc_mode={s[\"pqc_mode\"]}; need native_liboqs', file=sys.stderr)
    sys.exit(1)
print(f'pqc_mode={s[\"pqc_mode\"]}')
"

for i in $(seq 0 $(( ITERATIONS - 1 ))); do
  RUN_DIR=$(mktemp -d /tmp/pqvpn-bytes.XXXXXX)
  SERVER_NS=pqbytes-srv-$$-$i
  CLIENT_NS=pqbytes-cli-$$-$i
  PIDS=()

  cleanup_pq() {
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
    for pid in "${PIDS[@]:-}"; do wait "$pid" 2>/dev/null || true; done
    ip netns del "$SERVER_NS" 2>/dev/null || true
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    rm -rf "$RUN_DIR"
  }
  trap cleanup_pq EXIT INT TERM

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
  python -m vpn.cli identity generate \
    --private "$RUN_DIR/server/server.key" --public "$RUN_DIR/server/server.pub" 2>/dev/null
  python -m vpn.cli client-key generate \
    --private "$RUN_DIR/client/client.key" --public "$RUN_DIR/client/client.pub" 2>/dev/null
  python -m vpn.cli client authorize \
    "$(base64 -w0 "$RUN_DIR/client/client.pub")" \
    --database "$RUN_DIR/server/authorized.json" --client-id bench-client 2>/dev/null
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

  ip netns exec "$SERVER_NS" sysctl -q -w net.ipv4.ip_forward=1
  ip netns exec "$SERVER_NS" \
    python -m vpn.cli server --config "$RUN_DIR/server/server.toml" \
    >"$RUN_DIR/server.log" 2>&1 &
  PIDS+=("$!")
  sleep 2

  if ! kill -0 "${PIDS[0]}" 2>/dev/null; then
    echo "  run $i: PQ-VPN server failed to start" >&2
    cleanup_pq
    continue
  fi

  PCAP="$RUN_DIR/capture.pcap"
  ip netns exec "$SERVER_NS" tcpdump -i bench-s -w "$PCAP" -U 2>/dev/null &
  TCPDUMP_PID=$!
  PIDS+=("$TCPDUMP_PID")
  sleep 0.5

  ip -n "$CLIENT_NS" link del pqbench0 2>/dev/null || true
  ip netns exec "$CLIENT_NS" \
    python -m vpn.cli client connect --config "$RUN_DIR/client/client.toml" \
    >"$RUN_DIR/client.log" 2>&1 &
  CLIENT_PID=$!
  PIDS+=("$CLIENT_PID")

  CONNECTED=0
  for attempt in $(seq 1 60); do
    if ip netns exec "$CLIENT_NS" ping -c1 -W1 10.8.0.1 >/dev/null 2>&1; then
      CONNECTED=1
      break
    fi
    sleep 0.05
  done

  sleep 0.5
  kill "$TCPDUMP_PID" 2>/dev/null || true
  wait "$TCPDUMP_PID" 2>/dev/null || true

  if (( CONNECTED )); then
    STATS=$(tcpdump -r "$PCAP" -nn 2>/dev/null | head -n 1000 | wc -l)
    TOTAL_BYTES=$(tcpdump -r "$PCAP" -nn 2>/dev/null | awk '{sum += $NF} END {print sum+0}')
    WIRE_BYTES=$(stat -c%s "$PCAP" 2>/dev/null || echo 0)
    # Use capinfos if available for accurate byte count, otherwise parse tcpdump
    if command -v capinfos &>/dev/null; then
      WIRE_BYTES=$(capinfos -Tmd "$PCAP" 2>/dev/null | tail -1 | cut -f13 || echo "$WIRE_BYTES")
    fi
    # Count only TCP+UDP packets (handshake), exclude ICMP (ping probes)
    HS_PACKETS=$(tcpdump -r "$PCAP" -nn 'tcp or udp' 2>/dev/null | wc -l)
    HS_BYTES=$(tcpdump -r "$PCAP" -nn 'tcp or udp' 2>/dev/null | awk -F'length ' '{if(NF>1){split($2,a," ");sum+=a[1]}} END {print sum+0}')

    echo "pqvpn-net,lan,handshake_packets,$i,$HS_PACKETS,packets" >> "$CSV_FILE"
    echo "pqvpn-net,lan,handshake_wire_bytes,$i,$HS_BYTES,bytes" >> "$CSV_FILE"
    printf "  PQ-VPN run %d: %d packets, %d payload bytes\n" "$i" "$HS_PACKETS" "$HS_BYTES" >&2
  else
    echo "  PQ-VPN run $i: FAILED" >&2
  fi

  kill "$CLIENT_PID" 2>/dev/null || true
  wait "$CLIENT_PID" 2>/dev/null || true
  cleanup_pq
  trap - EXIT INT TERM
  sleep 1
done

# ---------- WireGuard ----------
if (( HAS_WG )); then
  echo "--- WireGuard handshake bytes ---" >&2

  SERVER_KEY=$(wg genkey)
  SERVER_PUB=$(echo "$SERVER_KEY" | wg pubkey)
  CLIENT_KEY=$(wg genkey)
  CLIENT_PUB=$(echo "$CLIENT_KEY" | wg pubkey)
  TMPDIR_WG=$(mktemp -d)

  for i in $(seq 0 $(( ITERATIONS - 1 ))); do
    SERVER_NS=wgbytes-srv-$$-$i
    CLIENT_NS=wgbytes-cli-$$-$i

    cleanup_wg() {
      ip netns exec "$CLIENT_NS" wg-quick down "$TMPDIR_WG/client.conf" 2>/dev/null || true
      ip netns exec "$SERVER_NS" wg-quick down "$TMPDIR_WG/server.conf" 2>/dev/null || true
      ip netns del "$CLIENT_NS" 2>/dev/null || true
      ip netns del "$SERVER_NS" 2>/dev/null || true
    }
    trap "cleanup_wg; rm -rf $TMPDIR_WG" EXIT INT TERM

    ip netns add "$SERVER_NS"
    ip netns add "$CLIENT_NS"
    ip link add veth_s_$$ type veth peer name veth_c_$$
    ip link set veth_s_$$ netns "$SERVER_NS"
    ip link set veth_c_$$ netns "$CLIENT_NS"
    ip netns exec "$SERVER_NS" ip addr add 192.168.99.1/24 dev veth_s_$$
    ip netns exec "$CLIENT_NS" ip addr add 192.168.99.2/24 dev veth_c_$$
    ip netns exec "$SERVER_NS" ip link set veth_s_$$ up mtu 1500
    ip netns exec "$CLIENT_NS" ip link set veth_c_$$ up mtu 1500
    ip netns exec "$SERVER_NS" ip link set lo up
    ip netns exec "$CLIENT_NS" ip link set lo up

    cat > "$TMPDIR_WG/server.conf" <<WGEOF
[Interface]
PrivateKey = $SERVER_KEY
ListenPort = 51820
Address = 10.99.0.1/24

[Peer]
PublicKey = $CLIENT_PUB
AllowedIPs = 10.99.0.2/32
WGEOF

    cat > "$TMPDIR_WG/client.conf" <<WGEOF
[Interface]
PrivateKey = $CLIENT_KEY
Address = 10.99.0.2/24

[Peer]
PublicKey = $SERVER_PUB
Endpoint = 192.168.99.1:51820
AllowedIPs = 10.99.0.0/24
WGEOF

    ip netns exec "$SERVER_NS" wg-quick up "$TMPDIR_WG/server.conf" 2>/dev/null

    PCAP="$TMPDIR_WG/capture-$i.pcap"
    ip netns exec "$SERVER_NS" tcpdump -i veth_s_$$ -w "$PCAP" -U 2>/dev/null &
    TCPDUMP_PID=$!
    sleep 0.5

    ip netns exec "$CLIENT_NS" wg-quick up "$TMPDIR_WG/client.conf" 2>/dev/null

    CONNECTED=0
    for attempt in $(seq 1 60); do
      if ip netns exec "$CLIENT_NS" ping -c1 -W1 10.99.0.1 >/dev/null 2>&1; then
        CONNECTED=1
        break
      fi
      sleep 0.05
    done

    sleep 0.5
    kill "$TCPDUMP_PID" 2>/dev/null || true
    wait "$TCPDUMP_PID" 2>/dev/null || true

    if (( CONNECTED )); then
      # WireGuard handshake is UDP port 51820
      HS_PACKETS=$(tcpdump -r "$PCAP" -nn 'udp port 51820' 2>/dev/null | wc -l)
      HS_BYTES=$(tcpdump -r "$PCAP" -nn 'udp port 51820' 2>/dev/null | awk -F'length ' '{if(NF>1){split($2,a," ");sum+=a[1]}} END {print sum+0}')

      echo "wireguard,lan,handshake_packets,$i,$HS_PACKETS,packets" >> "$CSV_FILE"
      echo "wireguard,lan,handshake_wire_bytes,$i,$HS_BYTES,bytes" >> "$CSV_FILE"
      printf "  WG run %d: %d packets, %d payload bytes\n" "$i" "$HS_PACKETS" "$HS_BYTES" >&2
    else
      echo "  WG run $i: FAILED" >&2
    fi

    cleanup_wg
    trap "rm -rf $TMPDIR_WG" EXIT INT TERM
    sleep 0.2
  done

  rm -rf "$TMPDIR_WG"
  trap - EXIT INT TERM
fi

echo "=== run_handshake_bytes: complete ===" >&2
