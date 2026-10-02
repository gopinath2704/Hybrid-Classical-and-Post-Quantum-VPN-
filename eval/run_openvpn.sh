#!/usr/bin/env bash
# Evaluate OpenVPN handshake latency.
# Requires: openvpn, root (for namespaces).
# Outputs CSV to stdout.
set -euo pipefail

ITERATIONS="${1:-30}"
OUT="${2:-/dev/stdout}"

if ! command -v openvpn &>/dev/null; then
    echo "SKIP: openvpn not found — install openvpn" >&2
    exit 0
fi

echo "suite,metric,value,unit" > "$OUT"
echo "OpenVPN evaluation: requires manual TLS cert setup — scaffold only" >&2
echo "openvpn,handshake_latency_ms,-1,ms" >> "$OUT"
