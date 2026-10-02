#!/usr/bin/env bash
# Verify all PQVPN v3 Tamarin lemmas.
# Usage: ./scripts/verify_formal.sh [--interactive]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
MODEL="$REPO_ROOT/formal/pqvpn_v3.spthy"

if ! command -v tamarin-prover &>/dev/null; then
    echo "ERROR: tamarin-prover not found. Install it first:" >&2
    echo "  Arch: sudo pacman -S tamarin-prover" >&2
    echo "  macOS: brew install tamarin-prover" >&2
    exit 1
fi

if [[ ! -f "$MODEL" ]]; then
    echo "ERROR: model not found at $MODEL" >&2
    exit 1
fi

if [[ "${1:-}" == "--interactive" ]]; then
    echo "Starting Tamarin interactive mode..."
    echo "Open http://127.0.0.1:3001 in your browser."
    exec tamarin-prover interactive "$MODEL"
fi

echo "PQVPN v3 Formal Verification"
echo "Model: $MODEL"
echo "Tamarin: $(tamarin-prover --version 2>&1 | head -1)"
echo ""
echo "Proving all lemmas..."
echo ""

if tamarin-prover --prove "$MODEL" 2>&1 | tee /dev/stderr | grep -q "verified\|falsified"; then
    echo ""
    echo "Verification complete. Check output above for results."
else
    echo ""
    echo "ERROR: Tamarin did not produce expected output." >&2
    exit 1
fi
