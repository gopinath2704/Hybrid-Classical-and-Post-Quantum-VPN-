#!/usr/bin/env bash
# Evaluate WireGuard + Rosenpass (fully PQ via Classic McEliece + Kyber).
# Requires: wg, rosenpass, root.
# Outputs CSV to stdout.
set -euo pipefail

ITERATIONS="${1:-30}"
OUT="${2:-/dev/stdout}"

if ! command -v rosenpass &>/dev/null; then
    echo "SKIP: rosenpass not found — install from https://rosenpass.eu" >&2
    exit 0
fi

echo "suite,metric,value,unit" > "$OUT"
echo "Rosenpass evaluation: requires rosenpass + wireguard setup — scaffold only" >&2
echo "rosenpass,handshake_latency_ms,-1,ms" >> "$OUT"
