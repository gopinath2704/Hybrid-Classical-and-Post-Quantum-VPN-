#!/usr/bin/env bash
# Evaluate WireGuard handshake/connect latency using the SAME namespace+veth
# topology, the SAME tc-netem profiles, and the SAME M1 definition (time from
# bringing the client up to first successful ping through the tunnel) as
# run_pqvpn_net.sh, so WireGuard and PQVPN are directly comparable.
#
# Requires: wg, wg-quick, ip, tc, root.
# Outputs CSV in the unified schema (+ per-row provenance):
#   system,profile,metric,run,value,unit,git_commit,liboqs_version,cpu_model,governor,kernel
#
# Usage (backwards compatible — profile defaults to lan):
#   sudo eval/run_wireguard.sh [iterations] [out] [profile]
set -euo pipefail

ITERATIONS="${1:-30}"
OUT="${2:-/dev/stdout}"
PROFILE="${3:-lan}"

# wg presence is checked FIRST so the harness exits non-zero (not silently
# exit 0 with an empty file) when WireGuard is not installed.
if ! command -v wg &>/dev/null; then
    echo "ERROR: wg not found — install wireguard-tools" >&2
    exit 1
fi

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=eval/netem_profiles.sh
source "$ROOT_DIR/eval/netem_profiles.sh"

if ! netem_profile_valid "$PROFILE"; then
    echo "unknown profile: $PROFILE (available: $NETEM_PROFILES)" >&2
    exit 1
fi
netem_require_tools || exit 1

MTU=$(netem_mtu "$PROFILE")
PROV=$(eval_provenance_fields)

TMPDIR_WG=$(mktemp -d)
SERVER_NS=wg_server_$$
CLIENT_NS=wg_client_$$
trap 'ip netns exec "$CLIENT_NS" wg-quick down "$TMPDIR_WG/client.conf" 2>/dev/null || true;
      ip netns exec "$SERVER_NS" wg-quick down "$TMPDIR_WG/server.conf" 2>/dev/null || true;
      ip netns del "$CLIENT_NS" 2>/dev/null || true;
      ip netns del "$SERVER_NS" 2>/dev/null || true;
      rm -rf "$TMPDIR_WG"' EXIT INT TERM

echo "$EVAL_CSV_HEADER" > "$OUT"

echo "=== run_wireguard: profile=$PROFILE rtt=$(netem_rtt "$PROFILE")ms loss=$(netem_loss "$PROFILE")% mtu=$MTU iterations=$ITERATIONS ===" >&2

SERVER_KEY=$(wg genkey)
SERVER_PUB=$(echo "$SERVER_KEY" | wg pubkey)
CLIENT_KEY=$(wg genkey)
CLIENT_PUB=$(echo "$CLIENT_KEY" | wg pubkey)

for i in $(seq 0 $(( ITERATIONS - 1 ))); do
    # Fresh namespaces + veth each iteration (fresh handshake every run).
    ip netns add "$SERVER_NS"
    ip netns add "$CLIENT_NS"
    ip link add veth_s_$$ type veth peer name veth_c_$$
    ip link set veth_s_$$ netns "$SERVER_NS"
    ip link set veth_c_$$ netns "$CLIENT_NS"
    ip netns exec "$SERVER_NS" ip addr add 192.168.99.1/24 dev veth_s_$$
    ip netns exec "$CLIENT_NS" ip addr add 192.168.99.2/24 dev veth_c_$$
    ip netns exec "$SERVER_NS" ip link set veth_s_$$ up mtu "$MTU"
    ip netns exec "$CLIENT_NS" ip link set veth_c_$$ up mtu "$MTU"
    ip netns exec "$SERVER_NS" ip link set lo up
    ip netns exec "$CLIENT_NS" ip link set lo up

    # Same netem as every other system on this profile.
    netem_apply "$SERVER_NS" veth_s_$$ "$PROFILE"
    netem_apply "$CLIENT_NS" veth_c_$$ "$PROFILE"

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
    START=$(date +%s%N)
    ip netns exec "$CLIENT_NS" wg-quick up "$TMPDIR_WG/client.conf" 2>/dev/null
    # M1: first successful ping through the tunnel (identical to PQVPN).
    CONNECTED=0
    for attempt in $(seq 1 60); do
        if ip netns exec "$CLIENT_NS" ping -c1 -W1 10.99.0.1 >/dev/null 2>&1; then
            CONNECTED=1
            break
        fi
        sleep 0.05
    done
    END=$(date +%s%N)

    if (( CONNECTED )); then
        LATENCY_MS=$(( (END - START) / 1000000 ))
        echo "wireguard,$PROFILE,connect_time_ms,$i,$LATENCY_MS,ms,$PROV" >> "$OUT"
        printf "  run %d: %d ms\n" "$i" "$LATENCY_MS" >&2
    else
        echo "  run $i: FAILED (timeout)" >&2
        echo "wireguard,$PROFILE,connect_time_ms,$i,-1,ms,$PROV" >> "$OUT"
    fi

    ip netns exec "$CLIENT_NS" wg-quick down "$TMPDIR_WG/client.conf" 2>/dev/null || true
    ip netns exec "$SERVER_NS" wg-quick down "$TMPDIR_WG/server.conf" 2>/dev/null || true
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$SERVER_NS" 2>/dev/null || true
    sleep 0.2
done

echo "WireGuard evaluation complete (profile=$PROFILE, $ITERATIONS iterations)" >&2
