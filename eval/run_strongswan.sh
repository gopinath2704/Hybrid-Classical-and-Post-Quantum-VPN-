#!/usr/bin/env bash
# Evaluate strongSwan (classical IKEv2/IPsec) connect time using the SAME
# namespace+veth topology, tc-netem profiles, and M1 definition (time to first
# ping through the tunnel) as run_pqvpn_net.sh and run_wireguard.sh.
#
# strongSwan is the mature classical IPsec baseline. We run charon in each
# namespace, load a minimal PSK IKEv2 config, then measure wall-clock from
# `swanctl --initiate` to the first successful ping through the tunnel.
#
# Requires: swanctl, charon (libcharon), ip, tc, root, kernel XFRM/IPsec.
# Outputs the unified schema (+ per-row provenance).
#
# NOTE: swanctl config paths and the charon binary location vary by distro.
# This runner targets strongSwan >= 5.9 with the vici/swanctl stack. Validate
# on the eval host first; it fails fast (non-zero, no empty CSV) if tools are
# missing or the tunnel never comes up.
#
# Usage (profile defaults to lan):
#   sudo eval/run_strongswan.sh [iterations] [out] [profile]
set -euo pipefail

ITERATIONS="${1:-30}"
OUT="${2:-/dev/stdout}"
PROFILE="${3:-lan}"

if ! command -v swanctl &>/dev/null; then
    echo "ERROR: swanctl not found — install strongSwan (strongswan-swanctl)" >&2
    exit 1
fi
CHARON_BIN=""
for cand in /usr/lib/ipsec/charon /usr/libexec/ipsec/charon /usr/lib/strongswan/charon; do
    [[ -x "$cand" ]] && CHARON_BIN="$cand" && break
done
if [[ -z "$CHARON_BIN" ]]; then
    echo "ERROR: charon daemon not found (looked in /usr/lib/ipsec, /usr/libexec/ipsec, /usr/lib/strongswan)" >&2
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

TMP=$(mktemp -d)
SERVER_NS=ss_server_$$
CLIENT_NS=ss_client_$$
SRV_CHARON=""
CLI_CHARON=""
cleanup() {
    [[ -n "$CLI_CHARON" ]] && kill "$CLI_CHARON" 2>/dev/null || true
    [[ -n "$SRV_CHARON" ]] && kill "$SRV_CHARON" 2>/dev/null || true
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$SERVER_NS" 2>/dev/null || true
    rm -rf "$TMP"
}
trap cleanup EXIT INT TERM

echo "$EVAL_CSV_HEADER" > "$OUT"
echo "=== run_strongswan: profile=$PROFILE rtt=$(netem_rtt "$PROFILE")ms loss=$(netem_loss "$PROFILE")% mtu=$MTU iterations=$ITERATIONS ===" >&2

PSK="pqvpn-eval-preshared-secret"

write_swanctl_conf() {
    # $1=dir $2=role(server|client) $3=local_ip $4=remote_ip
    local dir=$1 role=$2 local_ip=$3 remote_ip=$4
    mkdir -p "$dir/swanctl/conf.d"
    cat > "$dir/swanctl/swanctl.conf" <<CONF
connections {
    bench {
        version = 2
        local_addrs  = $local_ip
        remote_addrs = $remote_ip
        proposals = aes256-sha256-x25519
        local {
            auth = psk
            id = $role
        }
        remote {
            auth = psk
            id = $([[ $role == server ]] && echo client || echo server)
        }
        children {
            bench {
                local_ts  = $local_ip/32
                remote_ts = $remote_ip/32
                esp_proposals = aes256-sha256
                start_action = $([[ $role == client ]] && echo none || echo trap)
            }
        }
    }
}
secrets {
    ike-bench {
        id-server = server
        id-client = client
        secret = "$PSK"
    }
}
CONF
}

start_charon() {
    # $1=netns $2=confdir -> echoes the charon pid
    ip netns exec "$1" env STRONGSWAN_CONF=/dev/null SWANCTL_DIR="$2/swanctl" \
        "$CHARON_BIN" >"$2/charon.log" 2>&1 &
    echo $!
}

for i in $(seq 0 $(( ITERATIONS - 1 ))); do
    ip netns add "$SERVER_NS"
    ip netns add "$CLIENT_NS"
    ip link add veth_s_$$ type veth peer name veth_c_$$
    ip link set veth_s_$$ netns "$SERVER_NS"
    ip link set veth_c_$$ netns "$CLIENT_NS"
    ip netns exec "$SERVER_NS" ip addr add 192.168.97.1/24 dev veth_s_$$
    ip netns exec "$CLIENT_NS" ip addr add 192.168.97.2/24 dev veth_c_$$
    ip netns exec "$SERVER_NS" ip link set veth_s_$$ up mtu "$MTU"
    ip netns exec "$CLIENT_NS" ip link set veth_c_$$ up mtu "$MTU"
    ip netns exec "$SERVER_NS" ip link set lo up
    ip netns exec "$CLIENT_NS" ip link set lo up
    netem_apply "$SERVER_NS" veth_s_$$ "$PROFILE"
    netem_apply "$CLIENT_NS" veth_c_$$ "$PROFILE"

    write_swanctl_conf "$TMP/server" server 192.168.97.1 192.168.97.2
    write_swanctl_conf "$TMP/client" client 192.168.97.2 192.168.97.1

    SRV_CHARON=$(start_charon "$SERVER_NS" "$TMP/server")
    CLI_CHARON=$(start_charon "$CLIENT_NS" "$TMP/client")
    sleep 1
    ip netns exec "$SERVER_NS" env SWANCTL_DIR="$TMP/server/swanctl" swanctl --load-all >/dev/null 2>&1 || true
    ip netns exec "$CLIENT_NS" env SWANCTL_DIR="$TMP/client/swanctl" swanctl --load-all >/dev/null 2>&1 || true

    START=$(date +%s%N)
    ip netns exec "$CLIENT_NS" env SWANCTL_DIR="$TMP/client/swanctl" \
        swanctl --initiate --child bench >/dev/null 2>&1 || true
    # M1: first ping through the IPsec SA.
    CONNECTED=0
    for _ in $(seq 1 120); do
        if ip netns exec "$CLIENT_NS" ping -c1 -W1 192.168.97.1 >/dev/null 2>&1 \
           && ip netns exec "$CLIENT_NS" env SWANCTL_DIR="$TMP/client/swanctl" \
              swanctl --list-sas 2>/dev/null | grep -q INSTALLED; then
            CONNECTED=1
            break
        fi
        sleep 0.5
    done
    END=$(date +%s%N)

    if (( CONNECTED )); then
        LATENCY_MS=$(( (END - START) / 1000000 ))
        echo "strongswan,$PROFILE,connect_time_ms,$i,$LATENCY_MS,ms,$PROV" >> "$OUT"
        printf "  run %d: %d ms\n" "$i" "$LATENCY_MS" >&2
    else
        echo "  run $i: FAILED (timeout)" >&2
        echo "strongswan,$PROFILE,connect_time_ms,$i,-1,ms,$PROV" >> "$OUT"
    fi

    kill "$CLI_CHARON" 2>/dev/null || true
    kill "$SRV_CHARON" 2>/dev/null || true
    wait "$CLI_CHARON" 2>/dev/null || true
    wait "$SRV_CHARON" 2>/dev/null || true
    CLI_CHARON=""; SRV_CHARON=""
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$SERVER_NS" 2>/dev/null || true
    sleep 0.3
done

echo "strongSwan evaluation complete (profile=$PROFILE, $ITERATIONS iterations)" >&2
