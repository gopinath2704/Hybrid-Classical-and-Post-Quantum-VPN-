#!/usr/bin/env bash
# Reproduce all evaluation results, figures, and tables.
# Usage: ./reproduce.sh [--iterations N] [--skip-tests]
#
# Requires: Python 3.11+, liboqs 0.16.0 (native), pip-installed .[dev]
set -euo pipefail

ITERATIONS=50
SKIP_TESTS=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --iterations) ITERATIONS="$2"; shift 2 ;;
        --skip-tests) SKIP_TESTS=true; shift ;;
        *) echo "Usage: $0 [--iterations N] [--skip-tests]" >&2; exit 1 ;;
    esac
done

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR"

echo "================================================================="
echo "  PQVPN Reproducibility — $(date -Iseconds)"
echo "  Iterations: $ITERATIONS"
echo "================================================================="
echo

if [[ "$SKIP_TESTS" == false ]]; then
    echo "--- Step 1: Test suite ---"
    python -m pytest tests/ -q
    echo
fi

echo "--- Step 2: Evaluation campaign ---"
python eval/run_all.py --iterations "$ITERATIONS" --systems pqvpn
echo

LATEST=$(ls -td results/eval-* 2>/dev/null | head -1)
if [[ -z "$LATEST" ]]; then
    echo "ERROR: no results directory found" >&2
    exit 1
fi

echo "--- Step 3: Regenerate figures ---"
python eval/generate_tables.py --input "$LATEST/raw" --output "$LATEST/figures"
echo

echo "================================================================="
echo "  Done. Results: $LATEST"
echo "  Figures:       $LATEST/figures/"
echo "================================================================="
