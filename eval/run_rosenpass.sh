#!/usr/bin/env bash
# Evaluate Rosenpass (post-quantum WireGuard PSK) connect time using the SAME
# namespace+veth topology, tc-netem profiles, and M1 definition (time to first
# ping through the tunnel) as run_pqvpn_net.sh and run_wireguard.sh.
#
# Rosenpass performs a PQ key exchange (Classic McEliece + Kyber) and feeds a
# rotating pre-shared key into a WireGuard interface. We measure wall-clock
# from starting the client `rp exchange` to the first successful ping through
# the resulting tunnel — the same M1 as every other system.
#
# Requires: rp (rosenpass wrapper), wg, ip, tc, root.
# Outputs the unified schema (+ per-row provenance).
#
# NOTE: Rosenpass CLI surface has varied across releases. This runner targets
# the `rp` convenience wrapper (rosenpass >= 0.2). Validate on the eval host
# before trusting the numbers; it fails fast (non-zero, no empty CSV) if the
# tools are missing or the tunnel never comes up.
#
# Usage (profile defaults to lan):
#   sudo eval/run_rosenpass.sh [iterations] [out] [profile]
set -euo pipefail

ITERATIONS="${1:-30}"
OUT="${2:-/dev/stdout}"
PROFILE="${3:-lan}"

for tool in rp wg; do
    if ! command -v "$tool" &>/dev/null; then
        echo "ERROR: $tool not found — install rosenpass + wireguard-tools" >&2
        exit 1
    fi
done

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

TMP=$(mktemp -d)
SERVER_NS=rp_server_$$
CLIENT_NS=rp_client_$$
SRV_PID=""
cleanup() {
    [[ -n "$SRV_PID" ]] && kill "$SRV_PID" 2>/dev/null || true
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$SERVER_NS" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

echo "$EVAL_CSV_HEADER" > "$OUT"
echo "=== run_rosenpass: profile=$PROFILE rtt=$(netem_rtt "$PROFILE")ms loss=$(netem_loss "$PROFILE")% mtu=$MTU iterations=$ITERATIONS ===" >&2

# Generate Rosenpass keypairs once (long-term keys, like PQVPN identities).
rp genkey "$TMP/server.rosenpass-secret"
rp pubkey "$TMP/server.rosenpass-secret" "$TMP/server.rosenpass-public"
rp genkey "$TMP/client.rosenpass-secret"
rp pubkey "$TMP/client.rosenpass-secret" "$TMP/client.rosenpass-public"

for i in $(seq 0 $(( ITERATIONS - 1 ))); do
    ip netns add "$SERVER_NS"
    ip netns add "$CLIENT_NS"
    ip link add veth_s_$$ type veth peer name veth_c_$$
    ip link set veth_s_$$ netns "$SERVER_NS"
    ip link set veth_c_$$ netns "$CLIENT_NS"
    ip netns exec "$SERVER_NS" ip addr add 192.168.98.1/24 dev veth_s_$$
    ip netns exec "$CLIENT_NS" ip addr add 192.168.98.2/24 dev veth_c_$$
    ip netns exec "$SERVER_NS" ip link set veth_s_$$ up mtu "$MTU"
    ip netns exec "$CLIENT_NS" ip link set veth_c_$$ up mtu "$MTU"
    ip netns exec "$SERVER_NS" ip link set lo up
    ip netns exec "$CLIENT_NS" ip link set lo up
    netem_apply "$SERVER_NS" veth_s_$$ "$PROFILE"
    netem_apply "$CLIENT_NS" veth_c_$$ "$PROFILE"

    # Server side: rp exchange creates WG iface rp0 and rotates the PQ PSK.
    ip netns exec "$SERVER_NS" rp exchange \
        "$TMP/server.rosenpass-secret" \
        dev rp0 listen 192.168.98.1:9999 \
        peer "$TMP/client.rosenpass-public" allowed-ips 10.100.0.2/32 \
        >"$TMP/server.log" 2>&1 &
    SRV_PID=$!
    # Give the server a moment to create rp0 and bind its listener.
    for _ in $(seq 1 20); do
        ip netns exec "$SERVER_NS" ip link show rp0 &>/dev/null && break
        sleep 0.1
    done
    ip netns exec "$SERVER_NS" ip addr add 10.100.0.1/24 dev rp0 2>/dev/null || true
    ip netns exec "$SERVER_NS" ip link set rp0 up 2>/dev/null || true

    START=$(date +%s%N)
    ip netns exec "$CLIENT_NS" rp exchange \
        "$TMP/client.rosenpass-secret" \
        dev rp0 \
        peer "$TMP/server.rosenpass-public" endpoint 192.168.98.1:9999 \
        allowed-ips 10.100.0.1/32 \
        >"$TMP/client.log" 2>&1 &
    CLI_PID=$!
    for _ in $(seq 1 20); do
        ip netns exec "$CLIENT_NS" ip link show rp0 &>/dev/null && break
        sleep 0.1
    done
    ip netns exec "$CLIENT_NS" ip addr add 10.100.0.2/24 dev rp0 2>/dev/null || true
    ip netns exec "$CLIENT_NS" ip link set rp0 up 2>/dev/null || true

    # M1: first ping through the tunnel once the PQ PSK is installed.
    CONNECTED=0
    for _ in $(seq 1 120); do
        if ip netns exec "$CLIENT_NS" ping -c1 -W1 10.100.0.1 >/dev/null 2>&1; then
            CONNECTED=1
            break
        fi
        sleep 0.5
    done
    END=$(date +%s%N)

    if (( CONNECTED )); then
        LATENCY_MS=$(( (END - START) / 1000000 ))
        echo "rosenpass,$PROFILE,connect_time_ms,$i,$LATENCY_MS,ms,$PROV" >> "$OUT"
        printf "  run %d: %d ms\n" "$i" "$LATENCY_MS" >&2
    else
        echo "  run $i: FAILED (timeout)" >&2
        echo "rosenpass,$PROFILE,connect_time_ms,$i,-1,ms,$PROV" >> "$OUT"
    fi

    kill "$CLI_PID" 2>/dev/null || true
    kill "$SRV_PID" 2>/dev/null || true
    wait "$CLI_PID" 2>/dev/null || true
    wait "$SRV_PID" 2>/dev/null || true
    SRV_PID=""
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$SERVER_NS" 2>/dev/null || true
    sleep 0.3
done

echo "Rosenpass evaluation complete (profile=$PROFILE, $ITERATIONS iterations)" >&2
