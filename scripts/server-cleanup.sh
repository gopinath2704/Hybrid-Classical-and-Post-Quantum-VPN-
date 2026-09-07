#!/usr/bin/env bash
set -euo pipefail
RUNTIME=${PQVPN_RUNTIME_DIR:-/run/pqvpn}
install -d -m 700 "$RUNTIME"
exec 9>"$RUNTIME/firewall.lock"
flock -x 9
nft delete table inet pqvpn 2>/dev/null || true
nft delete table ip pqvpn_nat 2>/dev/null || true
nft delete table inet pqvpn_mangle 2>/dev/null || true
if [[ -f "$RUNTIME/ip_forward.prev" ]]; then
  PREVIOUS=$(cat "$RUNTIME/ip_forward.prev")
  [[ "$PREVIOUS" = 0 || "$PREVIOUS" = 1 ]]
  sysctl -w "net.ipv4.ip_forward=$PREVIOUS"
  rm "$RUNTIME/ip_forward.prev"
fi
echo 'Removed PQVPN tables and restored recorded IP forwarding state'
