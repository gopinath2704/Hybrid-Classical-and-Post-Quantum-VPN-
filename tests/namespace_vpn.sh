#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
RUN_DIR=$(mktemp -d /tmp/pqvpn-ns.XXXXXX)
SERVER_NS=pqvpn-server-$$
CLIENT1_NS=pqvpn-client1-$$
CLIENT2_NS=pqvpn-client2-$$
INTERNET_NS=pqvpn-internet-$$
PIDS=()

wait_bounded() {
  local pid=$1
  for _ in $(seq 1 100); do
    if ! kill -0 "$pid" 2>/dev/null; then wait "$pid"; return $?; fi
    sleep .1
  done
  echo "process $pid failed to exit within 10 seconds" >&2
  kill -KILL "$pid" 2>/dev/null || true
  wait "$pid" 2>/dev/null || true
  return 1
}

cleanup() {
  for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null || true; done
  for pid in "${PIDS[@]:-}"; do wait_bounded "$pid" || true; done
  PQVPN_RUNTIME_DIR="$RUN_DIR/fw" ip netns exec "$SERVER_NS" bash "$ROOT_DIR/scripts/server-cleanup.sh" >/dev/null 2>&1 || true
  for ns in "$CLIENT1_NS" "$CLIENT2_NS" "$SERVER_NS" "$INTERNET_NS"; do
    ip netns del "$ns" 2>/dev/null || true
  done
  rm -rf "$RUN_DIR"
}
trap cleanup EXIT INT TERM

for ns in "$SERVER_NS" "$CLIENT1_NS" "$CLIENT2_NS" "$INTERNET_NS"; do
  ip netns add "$ns"
  ip -n "$ns" link set lo up
done

ip link add pq-s1 type veth peer name pq-c1
ip link set pq-s1 netns "$SERVER_NS"
ip link set pq-c1 netns "$CLIENT1_NS"
ip link add pq-s2 type veth peer name pq-c2
ip link set pq-s2 netns "$SERVER_NS"
ip link set pq-c2 netns "$CLIENT2_NS"
ip link add pq-si type veth peer name pq-is
ip link set pq-si netns "$SERVER_NS"
ip link set pq-is netns "$INTERNET_NS"

ip -n "$SERVER_NS" addr add 192.0.2.1/24 dev pq-s1
ip -n "$CLIENT1_NS" addr add 192.0.2.2/24 dev pq-c1
ip -n "$SERVER_NS" addr add 192.0.3.1/24 dev pq-s2
ip -n "$CLIENT2_NS" addr add 192.0.3.2/24 dev pq-c2
ip -n "$SERVER_NS" addr add 198.51.100.1/24 dev pq-si
ip -n "$INTERNET_NS" addr add 198.51.100.2/24 dev pq-is
for spec in "$SERVER_NS pq-s1" "$SERVER_NS pq-s2" "$SERVER_NS pq-si" "$CLIENT1_NS pq-c1" "$CLIENT2_NS pq-c2" "$INTERNET_NS pq-is"; do
  read -r ns dev <<<"$spec"
  ip -n "$ns" link set "$dev" up
done
ip -n "$CLIENT1_NS" route add default via 192.0.2.1
ip -n "$CLIENT2_NS" route add default via 192.0.3.1
ip netns exec "$SERVER_NS" sysctl -q -w net.ipv4.ip_forward=0
ip -n "$INTERNET_NS" addr add 169.254.169.254/32 dev lo
ip -n "$INTERNET_NS" addr add 10.50.0.10/32 dev lo
ip -n "$SERVER_NS" route add 169.254.169.254/32 via 198.51.100.2
ip -n "$SERVER_NS" route add 10.50.0.10/32 via 198.51.100.2

mkdir -p "$RUN_DIR/server" "$RUN_DIR/client1" "$RUN_DIR/client2"
cd "$ROOT_DIR"
ALLOW_MOCK_PQC=1 python -m vpn.cli identity generate --private "$RUN_DIR/server/server.key" --public "$RUN_DIR/server/server.pub"
ALLOW_MOCK_PQC=1 python -m vpn.cli client-key generate --private "$RUN_DIR/client1/client.key" --public "$RUN_DIR/client1/client.pub"
ALLOW_MOCK_PQC=1 python -m vpn.cli client-key generate --private "$RUN_DIR/client2/client.key" --public "$RUN_DIR/client2/client.pub"
ALLOW_MOCK_PQC=1 python -m vpn.cli client authorize "$(base64 -w0 "$RUN_DIR/client1/client.pub")" --database "$RUN_DIR/server/authorized.json" --client-id client1
ALLOW_MOCK_PQC=1 python -m vpn.cli client authorize "$(base64 -w0 "$RUN_DIR/client2/client.pub")" --database "$RUN_DIR/server/authorized.json" --client-id client2
FINGERPRINT=$(sha256sum "$RUN_DIR/server/server.pub" | awk '{print $1}')

cat >"$RUN_DIR/server/server.toml" <<EOF
[server]
listen_host = "0.0.0.0"
control_port = 51820
udp_port = 51820
vpn_subnet = "10.8.0.0/24"
server_vpn_ip = "10.8.0.1"
max_clients = 8
handshake_timeout = 8
rekey_interval = 2
outbound_interface = "pq-si"
dns_servers = []
server_identity_private_key = "server.key"
server_identity_public_key = "server.pub"
authorized_clients_file = "authorized.json"
EOF
for idx in 1 2; do
  host=192.0.$((idx + 1)).1
  cat >"$RUN_DIR/client$idx/client.toml" <<EOF
[client]
server_host = "$host"
server_control_port = 51820
server_identity_fingerprint = "$FINGERPRINT"
server_identity_public_key = "../server/server.pub"
client_identity_private_key = "client.key"
full_tunnel = true
ping_interval = 0.5
ping_timeout = 0.5
dead_peer_timeout = 3.0
dns_mode = "none"
dns_servers = []
tun_name = "pqvpn$idx"
EOF
done

ip netns exec "$INTERNET_NS" python -m http.server 8080 --bind 0.0.0.0 >"$RUN_DIR/http.log" 2>&1 & PIDS+=("$!")
ip netns exec "$INTERNET_NS" python -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.bind(("198.51.100.2",9090));
while True:
 d,a=s.recvfrom(65535); s.sendto(d,a)' >"$RUN_DIR/udp.log" 2>&1 & PIDS+=("$!")
ALLOW_MOCK_PQC=1 ip netns exec "$SERVER_NS" python -m vpn.cli server --config "$RUN_DIR/server/server.toml" --allow-mock-pqc >"$RUN_DIR/server.log" 2>&1 & PIDS+=("$!")
sleep 2
PQVPN_RUNTIME_DIR="$RUN_DIR/fw" ip netns exec "$SERVER_NS" bash "$ROOT_DIR/scripts/server-setup.sh" "$RUN_DIR/server/server.toml"
# Repeat setup must preserve the original zero and produce one current policy.
PQVPN_RUNTIME_DIR="$RUN_DIR/fw" ip netns exec "$SERVER_NS" bash "$ROOT_DIR/scripts/server-setup.sh" "$RUN_DIR/server/server.toml"
test "$(cat "$RUN_DIR/fw/ip_forward.prev")" = 0

start_client() {
  local ns=$1 cfg=$2 tun=$3 log=$4
  ALLOW_MOCK_PQC=1 ip netns exec "$ns" python -m vpn.cli client connect --config "$cfg" --allow-mock-pqc >"$log" 2>&1 &
  PIDS+=("$!")
}
start_client "$CLIENT1_NS" "$RUN_DIR/client1/client.toml" pqvpn1 "$RUN_DIR/client1.log"
start_client "$CLIENT2_NS" "$RUN_DIR/client2/client.toml" pqvpn2 "$RUN_DIR/client2.log"

for _ in $(seq 1 40); do
  ip -n "$CLIENT1_NS" addr show pqvpn1 2>/dev/null | grep -q '10.8.0.' && ip -n "$CLIENT2_NS" addr show pqvpn2 2>/dev/null | grep -q '10.8.0.' && break
  sleep .25
done
IP1=$(ip -n "$CLIENT1_NS" -o -4 addr show pqvpn1 | awk '{print $4}' | cut -d/ -f1)
IP2=$(ip -n "$CLIENT2_NS" -o -4 addr show pqvpn2 | awk '{print $4}' | cut -d/ -f1)
test -n "$IP1" && test -n "$IP2" && test "$IP1" != "$IP2"
ip netns exec "$CLIENT1_NS" ping -c 2 -W 2 10.8.0.1
ip netns exec "$CLIENT1_NS" curl --noproxy "*" -fsS --max-time 5 http://198.51.100.2:8080/ >/dev/null
ip netns exec "$CLIENT2_NS" curl --noproxy "*" -fsS --max-time 5 http://198.51.100.2:8080/ >/dev/null
ip netns exec "$CLIENT1_NS" python -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(5); s.sendto(b"pqvpn-udp",("198.51.100.2",9090)); assert s.recv(64)==b"pqvpn-udp"'

# Real listeners make a successful TCP connection a policy failure.
ip netns exec "$SERVER_NS" python -m http.server 7070 --bind 0.0.0.0 >"$RUN_DIR/host.log" 2>&1 & PIDS+=("$!")
ip netns exec "$CLIENT2_NS" python -m http.server 7071 --bind "$IP2" >"$RUN_DIR/peer.log" 2>&1 & PIDS+=("$!")
sleep .5
# Verify the test listeners themselves work from their owning namespace.
ip netns exec "$SERVER_NS" curl --noproxy '*' -fsS --max-time 2 http://127.0.0.1:7070/ >/dev/null
ip netns exec "$CLIENT2_NS" curl --noproxy '*' -fsS --max-time 2 "http://$IP2:7071/" >/dev/null
for destination in "10.8.0.1:7070" "$IP2:7071" '169.254.169.254:8080' '10.50.0.10:8080'; do
  if ip netns exec "$CLIENT1_NS" curl --noproxy '*' -fsS --max-time 2 "http://$destination/" >/dev/null 2>&1; then
    echo "isolation failure: $destination was accessible" >&2; exit 1
  fi
done
# Allow only the private test service through WAN, then reconcile back to defaults.
cp "$RUN_DIR/server/server.toml" "$RUN_DIR/server/allowed.toml"
printf '\nallowed_forward_networks = ["10.50.0.10/32"]\n' >>"$RUN_DIR/server/allowed.toml"
PQVPN_RUNTIME_DIR="$RUN_DIR/fw" ip netns exec "$SERVER_NS" bash "$ROOT_DIR/scripts/server-setup.sh" "$RUN_DIR/server/allowed.toml"
ip netns exec "$CLIENT1_NS" curl --noproxy '*' -fsS --max-time 3 http://10.50.0.10:8080/ >/dev/null
PQVPN_RUNTIME_DIR="$RUN_DIR/fw" ip netns exec "$SERVER_NS" bash "$ROOT_DIR/scripts/server-setup.sh" "$RUN_DIR/server/server.toml"
if ip netns exec "$CLIENT1_NS" curl --noproxy '*' -fsS --max-time 2 http://10.50.0.10:8080/ >/dev/null 2>&1; then
  echo 'stale private allowlist survived reconciliation' >&2; exit 1
fi

# Exercise automatic rekey while repeated TCP and UDP application traffic flows.
for _ in $(seq 1 8); do
  ip netns exec "$CLIENT1_NS" curl --noproxy "*" -fsS --max-time 3 http://198.51.100.2:8080/ >/dev/null
  ip netns exec "$CLIENT1_NS" python -c 'import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); s.settimeout(3); s.sendto(b"flow",("198.51.100.2",9090)); assert s.recv(16)==b"flow"'
  sleep .5
done

# An authenticated client may not inject another session's inner source address.
ip -n "$CLIENT1_NS" addr add "$IP2/32" dev pqvpn1
if ip netns exec "$CLIENT1_NS" ping -I "$IP2" -c 1 -W 1 198.51.100.2; then
  echo "source spoof unexpectedly succeeded" >&2
  exit 1
fi
ip -n "$CLIENT1_NS" addr del "$IP2/32" dev pqvpn1

# Disconnect both clients, verify their original public routes survive, then reconnect client 1.
kill "${PIDS[3]}" "${PIDS[4]}"
wait_bounded "${PIDS[3]}"
wait_bounded "${PIDS[4]}"
ip -n "$CLIENT1_NS" route show default | grep -q 'via 192.0.2.1'
ip -n "$CLIENT2_NS" route show default | grep -q 'via 192.0.3.1'
sleep 1
start_client "$CLIENT1_NS" "$RUN_DIR/client1/client.toml" pqvpn1 "$RUN_DIR/client1-reconnect.log"
for _ in $(seq 1 40); do
  ip -n "$CLIENT1_NS" addr show pqvpn1 2>/dev/null | grep -q '10.8.0.' && break
  sleep .25
done
ip netns exec "$CLIENT1_NS" curl --noproxy "*" -fsS --max-time 5 http://198.51.100.2:8080/ >/dev/null
# A real UDP output blackhole must terminate the client even with TCP established.
BLACKHOLE_CLIENT=${PIDS[-1]}
ip netns exec "$SERVER_NS" nft add table inet pqvpn_test_blackhole
ip netns exec "$SERVER_NS" nft 'add chain inet pqvpn_test_blackhole output { type filter hook output priority filter; policy accept; }'
ip netns exec "$SERVER_NS" nft add rule inet pqvpn_test_blackhole output udp sport 51820 drop
# CLI reports a dead-peer error as nonzero; require bounded termination, then check restoration.
for _ in $(seq 1 100); do
  kill -0 "$BLACKHOLE_CLIENT" 2>/dev/null || break
  sleep .1
done
if kill -0 "$BLACKHOLE_CLIENT" 2>/dev/null; then echo 'dead-peer cleanup timed out' >&2; exit 1; fi
wait "$BLACKHOLE_CLIENT" || true
ip -n "$CLIENT1_NS" route show default | grep -q 'via 192.0.2.1'
if ip -n "$CLIENT1_NS" route show | grep -q 'dev pqvpn1'; then echo 'routes not restored after UDP blackhole' >&2; exit 1; fi
ip netns exec "$SERVER_NS" nft delete table inet pqvpn_test_blackhole
start_client "$CLIENT1_NS" "$RUN_DIR/client1/client.toml" pqvpn1 "$RUN_DIR/client1-after-blackhole.log"
for _ in $(seq 1 40); do
  ip -n "$CLIENT1_NS" addr show pqvpn1 2>/dev/null | grep -q '10.8.0.' && break
  sleep .25
done
ip netns exec "$CLIENT1_NS" curl --noproxy '*' -fsS --max-time 5 http://198.51.100.2:8080/ >/dev/null

# Run the quiet/idle regressions with real TUN in an isolated existing namespace.
# DNS is disabled here: host resolvectl must not be mutated from a netns test.
ALLOW_MOCK_PQC=1 ip netns exec "$INTERNET_NS" env PQVPN_TEST_NATIVE_TUN=1 python -m pytest -q \
  tests/test_session_activity.py tests/test_dead_peer.py -k 'keepalive_prevents or genuinely_idle or control_activity or udp_dead_peer or rekey_during'
PQVPN_RUNTIME_DIR="$RUN_DIR/fw" ip netns exec "$SERVER_NS" bash "$ROOT_DIR/scripts/server-cleanup.sh"
test "$(ip netns exec "$SERVER_NS" sysctl -n net.ipv4.ip_forward)" = 0
echo "namespace VPN integration succeeded: client IPs $IP1 and $IP2; UDP/TCP/rekey/spoof/disconnect/reconnect verified"
