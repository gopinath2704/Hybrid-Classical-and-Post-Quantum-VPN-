#!/usr/bin/env bash
# Verify all PQVPN v3 Tamarin lemmas (handshake + PCS).
# Usage: ./scripts/verify_formal.sh [--interactive]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
HS_MODEL="$REPO_ROOT/formal/pqvpn_v3.spthy"
PCS_MODEL="$REPO_ROOT/formal/pqvpn_v3_pcs.spthy"
RESULTS_DIR="$REPO_ROOT/formal/results"

if ! command -v tamarin-prover &>/dev/null; then
    echo "ERROR: tamarin-prover not found. Install it first:" >&2
    echo "  Arch: sudo pacman -S tamarin-prover" >&2
    echo "  macOS: brew install tamarin-prover" >&2
    exit 1
fi

for f in "$HS_MODEL" "$PCS_MODEL"; do
    if [[ ! -f "$f" ]]; then
        echo "ERROR: model not found at $f" >&2
        exit 1
    fi
done

if [[ "${1:-}" == "--interactive" ]]; then
    echo "Starting Tamarin interactive mode (handshake model)..."
    echo "Open http://127.0.0.1:3001 in your browser."
    exec tamarin-prover interactive "$HS_MODEL"
fi

# Expected lemmas per theory file.
declare -A HS_LEMMAS=(
  [protocol_completes]="exists-trace"
  [session_key_secrecy]="all-traces"
  [forward_secrecy]="all-traces"
  [server_auth]="all-traces"
  [client_auth]="all-traces"
  [kci_resistance_client]="all-traces"
  [kci_resistance_server]="all-traces"
)

declare -A PCS_LEMMAS=(
  [rehandshake_completes]="exists-trace"
  [passive_rehandshake_completes]="exists-trace"
  [pcs_control_keys_only]="all-traces"
  [pcs_passive_after_epoch_compromise]="all-traces"
  [attack_active_after_epoch_compromise]="exists-trace"
)

echo "PQVPN v3 Formal Verification"
echo "Tamarin: $(tamarin-prover --version 2>&1 | head -1)"
echo "Maude: $(maude --version 2>&1 | head -1)"
echo ""

mkdir -p "$RESULTS_DIR"
OUTPUT="$RESULTS_DIR/verify-$(date +%Y-%m-%d).txt"
: > "$OUTPUT"

FAIL=0

check_results() {
    local output_file="$1"
    shift
    local -n expected_lemmas=$1

    if grep -q "analysis incomplete" "$output_file"; then
        echo "FAIL: one or more lemmas have incomplete analysis" >&2
        FAIL=1
    fi

    if grep -q "falsified" "$output_file"; then
        while IFS= read -r line; do
            lemma=$(echo "$line" | grep -oP '\S+(?=\s.*falsified)')
            if [[ -n "$lemma" ]]; then
                kind="${expected_lemmas[$lemma]:-}"
                if [[ "$kind" != "exists-trace" ]]; then
                    echo "FAIL: $lemma falsified (expected verified)" >&2
                    FAIL=1
                fi
            fi
        done < <(grep "falsified" "$output_file")
    fi

    for lemma in "${!expected_lemmas[@]}"; do
        if ! grep -q "$lemma" "$output_file"; then
            echo "FAIL: expected lemma '$lemma' not found in output" >&2
            FAIL=1
        fi
    done
}

# ── Handshake ──────────────────────────────────────────────────────────
echo "═══ Handshake Model (7 lemmas) ═══"
echo "Model: $HS_MODEL"
echo ""

HS_OUT=$(mktemp)
tamarin-prover --prove "$HS_MODEL" 2>&1 | tee -a "$OUTPUT" | tee "$HS_OUT"
echo "" | tee -a "$OUTPUT"

check_results "$HS_OUT" HS_LEMMAS
rm -f "$HS_OUT"

# ── PCS ────────────────────────────────────────────────────────────────
echo "═══ PCS Model (5 lemmas) ═══"
echo "Model: $PCS_MODEL"
echo ""

PCS_OUT=$(mktemp)
tamarin-prover --heuristic=S --prove "$PCS_MODEL" 2>&1 | tee -a "$OUTPUT" | tee "$PCS_OUT"
echo "" | tee -a "$OUTPUT"

check_results "$PCS_OUT" PCS_LEMMAS
rm -f "$PCS_OUT"

# ── Final ──────────────────────────────────────────────────────────────
echo ""
echo "─── Result Check ───"

if [[ $FAIL -ne 0 ]]; then
    echo "Verification FAILED. See output above." >&2
    exit 1
fi

echo "All 12 lemmas verified as expected. Results saved to $OUTPUT"
