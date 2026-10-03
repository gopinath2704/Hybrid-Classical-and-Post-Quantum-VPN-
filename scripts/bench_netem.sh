#!/usr/bin/env bash
# Namespace-based network emulation setup for PQVPN benchmarks.
#
# Usage (requires root + native liboqs):
#   bash scripts/bench_netem.sh <profile> [--iterations N]
#
# This script creates isolated namespaces, applies tc netem rules,
# and delegates actual benchmark measurement to eval/run_pqvpn_net.sh.
set -euo pipefail

PROFILE=${1:?usage: bench_netem.sh <profile> [--iterations N]}
shift
ITERATIONS=50
while [[ $# -gt 0 ]]; do
  case $1 in
    --iterations) ITERATIONS=$2; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 1 ;;
  esac
done

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)

echo "bench_netem.sh: delegating to eval/run_pqvpn_net.sh $PROFILE --iterations $ITERATIONS"
exec bash "$ROOT_DIR/eval/run_pqvpn_net.sh" "$PROFILE" --iterations "$ITERATIONS"
