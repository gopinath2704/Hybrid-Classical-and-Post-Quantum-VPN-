#!/usr/bin/env bash
# Evaluate strongSwan IKEv2 with ML-KEM (RFC 9370 additional key exchange).
# Requires: swanctl, charon-systemd, liboqs-enabled strongSwan build, root.
# Outputs CSV to stdout.
set -euo pipefail

ITERATIONS="${1:-30}"
OUT="${2:-/dev/stdout}"

if ! command -v swanctl &>/dev/null; then
    echo "SKIP: swanctl not found — install strongSwan with PQ support" >&2
    exit 0
fi

echo "suite,metric,value,unit" > "$OUT"
echo "strongSwan evaluation: requires PQ-enabled build — scaffold only" >&2
echo "strongswan-mlkem,handshake_latency_ms,-1,ms" >> "$OUT"
