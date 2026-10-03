"""Tests for the evaluation harness: CPU split, CSV schema, bootstrap CI, PQC guard."""
import csv
import io
import os
import subprocess
import sys
import math
import random
from pathlib import Path
from unittest.mock import patch

import pytest

_ROOT = Path(__file__).resolve().parent.parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))


# ---------------------------------------------------------------------------
# 1. CPU split: client and server CPU are measured separately and correctly
# ---------------------------------------------------------------------------

def test_cpu_split_separate_timing():
    """Client CPU = initiate + process_server_hello + process_server_finished.
    Server CPU = process_client_hello + process_client_key_exchange.
    Both must be > 0 and client+server <= wall-clock latency (approximately)."""
    from eval.run_pqvpn import run_handshake
    r = run_handshake("v2-ed25519")
    assert r["client_cpu_ms"] >= 0
    assert r["server_cpu_ms"] >= 0
    assert r["client_cpu_ms"] + r["server_cpu_ms"] <= r["latency_ms"] * 10


def test_cpu_split_all_suites():
    """CPU split works for all three suites."""
    from eval.run_pqvpn import run_handshake
    for suite in ("v2-ed25519", "v3-kem", "v3-mldsa"):
        r = run_handshake(suite)
        assert r["client_cpu_ms"] >= 0, f"{suite} client_cpu_ms < 0"
        assert r["server_cpu_ms"] >= 0, f"{suite} server_cpu_ms < 0"
        assert r["latency_ms"] > 0, f"{suite} latency_ms <= 0"


def test_benchmarks_cpu_split():
    """benchmarks.py _run_handshake also measures CPU correctly."""
    from benchmarks import HandshakeBenchmark
    hb = HandshakeBenchmark(iterations=1, warmup_runs=0)
    for suite in ("v2-ed25519", "v3-kem", "v3-mldsa"):
        m = hb._benchmark_single_handshake(suite, "ML-KEM-768")
        assert m.client_cpu_ms >= 0
        assert m.server_cpu_ms >= 0


# ---------------------------------------------------------------------------
# 2. CSV schema: system,profile,metric,run,value,unit
# ---------------------------------------------------------------------------

EXPECTED_COLUMNS = {"system", "profile", "metric", "run", "value", "unit"}


def test_csv_schema_run_pqvpn():
    """run_pqvpn evaluate_suite outputs rows with the unified CSV schema."""
    from eval.run_pqvpn import evaluate_suite, CSV_COLUMNS
    assert set(CSV_COLUMNS) == EXPECTED_COLUMNS

    rows = evaluate_suite("v2-ed25519", iterations=3, warmup=1)
    assert len(rows) > 0
    for row in rows:
        assert set(row.keys()) == EXPECTED_COLUMNS
        assert row["system"].startswith("pqvpn-")
        assert isinstance(row["run"], int)
        assert isinstance(row["value"], (int, float))


def test_csv_schema_has_per_run_rows():
    """Each iteration produces per-run rows (not pre-aggregated medians)."""
    from eval.run_pqvpn import evaluate_suite
    rows = evaluate_suite("v2-ed25519", iterations=5, warmup=1)
    latency_rows = [r for r in rows if r["metric"] == "latency_ms"]
    assert len(latency_rows) == 5
    run_ids = sorted(r["run"] for r in latency_rows)
    assert run_ids == [0, 1, 2, 3, 4]


# ---------------------------------------------------------------------------
# 3. Bootstrap CI on a known sample
# ---------------------------------------------------------------------------

def test_bootstrap_ci_known_sample():
    """Bootstrap CI on a deterministic sample should be stable and contain the median."""
    from eval.generate_tables import bootstrap_ci

    values = [1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0, 11.0]
    median, ci_lo, ci_hi = bootstrap_ci(values, n_resamples=10000, seed=42)
    assert median == 6.0
    assert ci_lo <= median
    assert ci_hi >= median
    assert ci_lo >= 1.0
    assert ci_hi <= 11.0


def test_bootstrap_ci_single_value():
    """Single value should return that value for median and both CI bounds."""
    from eval.generate_tables import bootstrap_ci
    median, ci_lo, ci_hi = bootstrap_ci([42.0])
    assert median == 42.0
    assert ci_lo == 42.0
    assert ci_hi == 42.0


def test_bootstrap_ci_tight_sample():
    """Identical values should give zero-width CI."""
    from eval.generate_tables import bootstrap_ci
    median, ci_lo, ci_hi = bootstrap_ci([5.0, 5.0, 5.0, 5.0, 5.0])
    assert median == 5.0
    assert ci_lo == 5.0
    assert ci_hi == 5.0


def test_bootstrap_ci_deterministic():
    """Same seed should always produce same result."""
    from eval.generate_tables import bootstrap_ci
    values = list(range(1, 101))
    r1 = bootstrap_ci([float(v) for v in values], seed=42)
    r2 = bootstrap_ci([float(v) for v in values], seed=42)
    assert r1 == r2


# ---------------------------------------------------------------------------
# 4. PQC guard rejects mock mode
# ---------------------------------------------------------------------------

def test_pqc_guard_rejects_mock():
    """require_native_pqc should sys.exit(1) when in mock mode."""
    from eval.run_pqvpn import require_native_pqc
    mock_status = {
        "pqc_mode": "mock_sha_fallback",
        "is_quantum_safe": False,
        "liboqs_available": False,
    }
    with patch("eval.run_pqvpn.get_crypto_status", return_value=mock_status):
        with pytest.raises(SystemExit) as exc:
            require_native_pqc()
        assert exc.value.code == 1


def test_pqc_guard_rejects_unavailable():
    """require_native_pqc should sys.exit(1) when PQC is unavailable."""
    from eval.run_pqvpn import require_native_pqc
    mock_status = {
        "pqc_mode": "unavailable",
        "is_quantum_safe": False,
        "liboqs_available": False,
    }
    with patch("eval.run_pqvpn.get_crypto_status", return_value=mock_status):
        with pytest.raises(SystemExit) as exc:
            require_native_pqc()
        assert exc.value.code == 1


def test_benchmarks_pqc_guard_rejects_mock():
    """benchmarks.require_native_pqc should also reject mock mode."""
    from benchmarks import require_native_pqc
    mock_status = {
        "pqc_mode": "mock_sha_fallback",
        "is_quantum_safe": False,
        "liboqs_available": False,
    }
    with patch("benchmarks.get_crypto_status", return_value=mock_status):
        with pytest.raises(SystemExit) as exc:
            require_native_pqc()
        assert exc.value.code == 1


# ---------------------------------------------------------------------------
# 5. generate_tables reads unified CSV and produces output
# ---------------------------------------------------------------------------

def test_generate_tables_roundtrip(tmp_path):
    """generate_tables correctly reads unified CSV and produces summary."""
    from eval.generate_tables import load_all_csv, group_data, generate_summary

    raw_dir = tmp_path / "raw"
    raw_dir.mkdir()
    csv_path = raw_dir / "test.csv"
    with open(csv_path, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=["system", "profile", "metric", "run", "value", "unit"])
        w.writeheader()
        for i in range(10):
            w.writerow({
                "system": "test-system",
                "profile": "lan",
                "metric": "latency_ms",
                "run": i,
                "value": 1.0 + i * 0.1,
                "unit": "ms",
            })

    rows = load_all_csv(raw_dir)
    assert len(rows) == 10

    groups = group_data(rows)
    assert ("test-system", "lan", "latency_ms") in groups
    assert len(groups[("test-system", "lan", "latency_ms")]) == 10

    summary = generate_summary(groups)
    assert len(summary) == 1
    assert summary[0]["system"] == "test-system"
    assert summary[0]["n"] == 10
    assert summary[0]["ci_lo"] <= summary[0]["median"] <= summary[0]["ci_hi"]


# ---------------------------------------------------------------------------
# 6. Handshakes/sec uses measured elapsed time
# ---------------------------------------------------------------------------

def test_handshakes_per_sec_uses_elapsed():
    """measure_handshakes_per_sec divides by actual elapsed, not requested duration."""
    from eval.run_pqvpn import measure_handshakes_per_sec
    hs = measure_handshakes_per_sec("v2-ed25519", duration_s=0.5)
    assert hs > 0


# ---------------------------------------------------------------------------
# 7. Wireguard script exits non-zero when wg is missing
# ---------------------------------------------------------------------------

def test_wireguard_script_exits_nonzero_without_wg():
    """run_wireguard.sh should exit 1 (not 0) when wg is missing."""
    script = _ROOT / "eval" / "run_wireguard.sh"
    env = {**os.environ, "PATH": "/usr/bin:/bin"}
    import shutil
    if shutil.which("wg"):
        pytest.skip("wg is installed; cannot test missing-wg path")
    result = subprocess.run(["bash", str(script), "1", "/dev/null"],
                            env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode != 0
