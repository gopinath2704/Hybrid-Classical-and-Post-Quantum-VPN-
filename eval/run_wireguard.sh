#!/usr/bin/env bash
# Evaluate WireGuard handshake latency using the same namespace+veth topology
# and M1 definition (time to first ping through the tunnel) as run_pqvpn_net.sh.
#
# Requires: wg, wg-quick, root.
# Outputs CSV in the unified schema: system,profile,metric,run,value,unit
set -euo pipefail

ITERATIONS="${1:-30}"
OUT="${2:-/dev/stdout}"

if ! command -v wg &>/dev/null; then
    echo "ERROR: wg not found — install wireguard-tools" >&2
    exit 1
fi

TMPDIR_WG=$(mktemp -d)
trap 'rm -rf "$TMPDIR_WG"; ip netns del wg_server_$$ 2>/dev/null || true; ip netns del wg_client_$$ 2>/dev/null || true' EXIT INT TERM

echo "system,profile,metric,run,value,unit" > "$OUT"

SERVER_KEY=$(wg genkey)
SERVER_PUB=$(echo "$SERVER_KEY" | wg pubkey)
CLIENT_KEY=$(wg genkey)
CLIENT_PUB=$(echo "$CLIENT_KEY" | wg pubkey)

for i in $(seq 0 $(( ITERATIONS - 1 ))); do
    # Create namespaces
    ip netns add wg_server_$$ 2>/dev/null || true
    ip netns add wg_client_$$ 2>/dev/null || true
    ip link add veth_s_$$ type veth peer name veth_c_$$
    ip link set veth_s_$$ netns wg_server_$$
    ip link set veth_c_$$ netns wg_client_$$
    ip netns exec wg_server_$$ ip addr add 192.168.99.1/24 dev veth_s_$$
    ip netns exec wg_client_$$ ip addr add 192.168.99.2/24 dev veth_c_$$
    ip netns exec wg_server_$$ ip link set veth_s_$$ up
    ip netns exec wg_client_$$ ip link set veth_c_$$ up
    ip netns exec wg_server_$$ ip link set lo up
    ip netns exec wg_client_$$ ip link set lo up

    # Server WG config
    cat > "$TMPDIR_WG/server.conf" <<WGEOF
[Interface]
PrivateKey = $SERVER_KEY
ListenPort = 51820
Address = 10.99.0.1/24

[Peer]
PublicKey = $CLIENT_PUB
AllowedIPs = 10.99.0.2/32
WGEOF

    # Client WG config
    cat > "$TMPDIR_WG/client.conf" <<WGEOF
[Interface]
PrivateKey = $CLIENT_KEY
Address = 10.99.0.2/24

[Peer]
PublicKey = $SERVER_PUB
Endpoint = 192.168.99.1:51820
AllowedIPs = 10.99.0.0/24
WGEOF

    ip netns exec wg_server_$$ wg-quick up "$TMPDIR_WG/server.conf" 2>/dev/null
    START=$(date +%s%N)
    ip netns exec wg_client_$$ wg-quick up "$TMPDIR_WG/client.conf" 2>/dev/null
    # M1: first successful ping through the tunnel (same as PQVPN definition)
    ip netns exec wg_client_$$ ping -c1 -W2 10.99.0.1 >/dev/null 2>&1
    END=$(date +%s%N)
    LATENCY_MS=$(( (END - START) / 1000000 ))

    echo "wireguard,lan,connect_time_ms,$i,$LATENCY_MS,ms" >> "$OUT"

    # Cleanup
    ip netns exec wg_client_$$ wg-quick down "$TMPDIR_WG/client.conf" 2>/dev/null || true
    ip netns exec wg_server_$$ wg-quick down "$TMPDIR_WG/server.conf" 2>/dev/null || true
    ip netns del wg_client_$$ 2>/dev/null || true
    ip netns del wg_server_$$ 2>/dev/null || true
done

echo "WireGuard evaluation complete ($ITERATIONS iterations)" >&2
