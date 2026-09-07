#!/usr/bin/env bash
set -euo pipefail
PROJECT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
CONFIG=${1:-}
[[ -z "$CONFIG" || "$CONFIG" = /* ]] || CONFIG="$PWD/$CONFIG"
cd "$PROJECT_DIR"
# Validate all TOML values before any network or firewall mutation.
mapfile -t settings < <("${PQVPN_PYTHON:-python3}" -m vpn.firewall "$CONFIG" '' settings)
[[ ${#settings[@]} -eq 2 ]] || exit 1
WAN=${settings[0]}
MANAGE=${settings[1]}
WAN=${WAN:-$(ip -4 route show default | awk 'NR==1 {print $5}')}
test -n "$WAN"
ip link show dev "$WAN" >/dev/null
RULES=$(mktemp)
trap 'rm -f "$RULES"' EXIT
"${PQVPN_PYTHON:-python3}" -m vpn.firewall "$CONFIG" "$WAN" rules >"$RULES"
RUNTIME=${PQVPN_RUNTIME_DIR:-/run/pqvpn}
install -d -m 700 "$RUNTIME"
exec 9>"$RUNTIME/firewall.lock"
flock -x 9
PREVIOUS=$(sysctl -n net.ipv4.ip_forward)
[[ "$PREVIOUS" = 0 || "$PREVIOUS" = 1 ]]
if [[ "$MANAGE" = 0 && "$PREVIOUS" != 1 ]]; then
  echo 'IP forwarding disabled and manage_ip_forward=false' >&2
  exit 1
fi
if [[ "$MANAGE" = 1 && ! -f "$RUNTIME/ip_forward.prev" ]]; then
  (umask 077; printf '%s\n' "$PREVIOUS" >"$RUNTIME/ip_forward.prev.tmp")
  mv "$RUNTIME/ip_forward.prev.tmp" "$RUNTIME/ip_forward.prev"
fi
# Atomic nft transaction replaces exclusively owned tables; unrelated tables stay intact.
BATCH=$(mktemp)
trap 'rm -f "$RULES" "$BATCH"' EXIT
for spec in 'inet pqvpn' 'ip pqvpn_nat' 'inet pqvpn_mangle'; do
  read -r family table <<<"$spec"
  if nft list table "$family" "$table" >/dev/null 2>&1; then
    printf 'delete table %s %s\n' "$family" "$table" >>"$BATCH"
  fi
done
cat "$RULES" >>"$BATCH"
nft -c -f "$BATCH"
nft -f "$BATCH"
if [[ "$MANAGE" = 1 ]]; then sysctl -w net.ipv4.ip_forward=1; fi
echo "PQVPN firewall reconciled via $WAN; TUN peers, host services and private destinations isolated"
