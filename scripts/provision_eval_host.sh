#!/usr/bin/env bash
# Provision a bare-metal / VM Ubuntu host for the PQ-VPN evaluation campaign.
#
# Installs the userspace tooling (iproute2, tcpdump, iperf3, wireguard-tools),
# builds and installs native liboqs, creates the project venv with the pinned
# dependencies, then ASSERTS the kernel prerequisites the campaign cannot run
# without — tc netem, kernel WireGuard, and the ability to load kernel modules
# (or the built-in equivalents of those features) — failing loudly with a
# non-zero exit if any are missing.
#
# This script does NOT emit any measurement numbers. Everything from Step 0 of
# the evaluation (eval/run_pqvpn_net.sh and friends) runs AFTER this succeeds.
#
# Usage (must be root):
#   sudo bash scripts/provision_eval_host.sh [options]
#
# Options:
#   --liboqs-prefix DIR   Install prefix for native liboqs (default /usr/local)
#   --venv DIR            Python venv path (default <repo>/.venv)
#   --python BIN          Interpreter used to create the venv (default python3;
#                         constraints-tested.txt is validated on CPython 3.14.x)
#   --skip-apt            Skip apt package installation
#   --skip-liboqs         Skip the native liboqs build/install
#   --skip-python         Skip venv creation + pip install
#   --skip-crypto-verify  Skip the final native-liboqs runtime verification
#   -h, --help            Show this help
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

LIBOQS_PREFIX=/usr/local
VENV_DIR="$ROOT_DIR/.venv"
PYTHON_BIN=python3
# constraints-tested.txt pins (numpy/pandas/matplotlib) are the versions
# validated against this CPython series; other interpreters will not resolve.
TESTED_PY_SERIES="3.14"
SKIP_APT=false
SKIP_LIBOQS=false
SKIP_PYTHON=false
SKIP_CRYPTO_VERIFY=false

APT_PACKAGES=(
  iproute2 tcpdump iperf3 wireguard-tools
  build-essential cmake ninja-build git pkg-config
  python3 python3-venv python3-pip
)

# ---- pretty output -----------------------------------------------------------
if [[ -t 1 ]]; then
  C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_BLU=$'\033[34m'; C_RST=$'\033[0m'
else
  C_RED=""; C_GRN=""; C_YEL=""; C_BLU=""; C_RST=""
fi
section() { printf '\n%s===== %s =====%s\n' "$C_BLU" "$1" "$C_RST"; }
ok()      { printf '%s[ OK ]%s %s\n'   "$C_GRN" "$C_RST" "$1"; }
warn()    { printf '%s[WARN]%s %s\n'   "$C_YEL" "$C_RST" "$1"; }
fail()    { printf '%s[FAIL]%s %s\n'   "$C_RED" "$C_RST" "$1"; }

usage() { awk 'NR>1 && /^#/{sub(/^# ?/,""); print; next} NR>1{exit}' "${BASH_SOURCE[0]}"; exit "${1:-0}"; }

# ---- arg parsing -------------------------------------------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --liboqs-prefix) LIBOQS_PREFIX="$2"; shift 2 ;;
    --venv)          VENV_DIR="$2"; shift 2 ;;
    --python)        PYTHON_BIN="$2"; shift 2 ;;
    --skip-apt)      SKIP_APT=true; shift ;;
    --skip-liboqs)   SKIP_LIBOQS=true; shift ;;
    --skip-python)   SKIP_PYTHON=true; shift ;;
    --skip-crypto-verify) SKIP_CRYPTO_VERIFY=true; shift ;;
    -h|--help)       usage 0 ;;
    *) fail "unknown argument: $1"; usage 1 ;;
  esac
done
[[ "$LIBOQS_PREFIX" = /* ]] || { fail "--liboqs-prefix must be absolute"; exit 1; }

if [[ "$(id -u)" -ne 0 ]]; then
  fail "must run as root (needs apt, ldconfig, and CAP_NET_ADMIN for the kernel probes)"
  exit 1
fi

KERNEL_RELEASE="$(uname -r)"
echo "PQ-VPN eval-host provisioner"
echo "  repo:          $ROOT_DIR"
echo "  kernel:        $KERNEL_RELEASE"
echo "  liboqs prefix: $LIBOQS_PREFIX"
echo "  venv:          $VENV_DIR"

# =============================================================================
# 1. Userspace tooling
# =============================================================================
section "1. apt packages"
if $SKIP_APT; then
  warn "skipping apt install (--skip-apt)"
else
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  apt-get install -y -q "${APT_PACKAGES[@]}"
  ok "installed: ${APT_PACKAGES[*]}"
fi

# Make sure the tools are reachable even if PATH omits the admin dirs.
export PATH="$PATH:/usr/sbin:/sbin"
for t in ip tc tcpdump iperf3 wg; do
  if command -v "$t" >/dev/null 2>&1; then
    ok "$t -> $(command -v "$t")"
  else
    fail "$t not found on PATH after install"
    exit 1
  fi
done

# =============================================================================
# 2. KERNEL GATE  — assert before the expensive liboqs build so a bad host
#    fails fast. Functional probes are authoritative; kernel config is read
#    for diagnostics and to satisfy the explicit CONFIG_* assertions.
# =============================================================================
section "2. kernel capability gate"

GATE_FAILURES=()

# Read the running kernel's build config, if exposed.
KCONFIG="$(mktemp)"
trap 'rm -f "$KCONFIG"' EXIT
if zcat /proc/config.gz >"$KCONFIG" 2>/dev/null && [[ -s "$KCONFIG" ]]; then
  KCONFIG_SRC="/proc/config.gz"
elif [[ -r "/boot/config-$KERNEL_RELEASE" ]]; then
  cat "/boot/config-$KERNEL_RELEASE" >"$KCONFIG"
  KCONFIG_SRC="/boot/config-$KERNEL_RELEASE"
else
  : >"$KCONFIG"
  KCONFIG_SRC=""
fi
if [[ -n "$KCONFIG_SRC" ]]; then
  echo "  kernel config: $KCONFIG_SRC"
else
  warn "kernel config not readable; relying on functional probes only"
fi

# cfg_state SYMBOL -> prints y|m|n|unknown
cfg_state() {
  local sym="$1"
  [[ -s "$KCONFIG" ]] || { echo unknown; return; }
  if grep -q "^${sym}=y" "$KCONFIG"; then echo y
  elif grep -q "^${sym}=m" "$KCONFIG"; then echo m
  elif grep -q "^# ${sym} is not set" "$KCONFIG" || ! grep -q "^${sym}=" "$KCONFIG"; then echo n
  else echo unknown; fi
}

# Functional netem probe: build netem on a veth inside a throwaway netns.
probe_netem() {
  command -v modprobe >/dev/null 2>&1 && modprobe sch_netem >/dev/null 2>&1 || true
  local ns="provn_$$"
  ip netns add "$ns" 2>/dev/null || return 2
  local rc=1
  if ip -n "$ns" link add vp0 type veth peer name vp1 2>/dev/null \
     && ip -n "$ns" link set vp0 up 2>/dev/null \
     && ip netns exec "$ns" tc qdisc add dev vp0 root netem delay 10ms loss 1% 2>/dev/null; then
    rc=0
  fi
  ip netns del "$ns" 2>/dev/null || true
  return $rc
}

# Functional WireGuard probe: a kernel wg interface requires the kernel
# module/built-in — the userspace `wg` tool alone cannot create it.
probe_wireguard() {
  command -v modprobe >/dev/null 2>&1 && modprobe wireguard >/dev/null 2>&1 || true
  local ns="provw_$$"
  ip netns add "$ns" 2>/dev/null || return 2
  local rc=1
  if ip -n "$ns" link add wgprov type wireguard 2>/dev/null; then
    ip -n "$ns" link del wgprov 2>/dev/null || true
    rc=0
  fi
  ip netns del "$ns" 2>/dev/null || true
  return $rc
}

# --- assert: tc netem (CONFIG_NET_SCH_NETEM) ---
NETEM_CFG="$(cfg_state CONFIG_NET_SCH_NETEM)"
if probe_netem; then
  NETEM_OK=true
  ok "tc netem usable (CONFIG_NET_SCH_NETEM=$NETEM_CFG) — qdisc applied to a test veth"
else
  NETEM_OK=false
  fail "tc netem NOT usable (CONFIG_NET_SCH_NETEM=$NETEM_CFG) — every network profile depends on it"
  GATE_FAILURES+=("CONFIG_NET_SCH_NETEM: tc netem qdisc could not be applied")
fi

# --- assert: kernel WireGuard (CONFIG_WIREGUARD) ---
WG_CFG="$(cfg_state CONFIG_WIREGUARD)"
if probe_wireguard; then
  WG_OK=true
  ok "kernel WireGuard usable (CONFIG_WIREGUARD=$WG_CFG) — 'ip link add type wireguard' succeeded"
else
  WG_OK=false
  fail "kernel WireGuard NOT usable (CONFIG_WIREGUARD=$WG_CFG) — the classical WireGuard baseline needs it"
  GATE_FAILURES+=("CONFIG_WIREGUARD: kernel wireguard interface could not be created")
fi

# --- assert: module loading, OR the built-in equivalents ---
MODULES_CFG="$(cfg_state CONFIG_MODULES)"
MODLOAD_OK=false
MODLOAD_WHY=""
if [[ "$MODULES_CFG" == y ]] && command -v modprobe >/dev/null 2>&1 \
   && [[ -d "/lib/modules/$KERNEL_RELEASE" ]]; then
  MODLOAD_OK=true
  MODLOAD_WHY="CONFIG_MODULES=y, modprobe present, /lib/modules/$KERNEL_RELEASE exists"
elif [[ "$NETEM_CFG" == y && "$WG_CFG" == y ]]; then
  MODLOAD_OK=true
  MODLOAD_WHY="netem and WireGuard are both built-in (=y) — module loading not required"
elif $NETEM_OK && $WG_OK && [[ -z "$KCONFIG_SRC" ]]; then
  MODLOAD_OK=true
  MODLOAD_WHY="kernel config unreadable, but both required features probed usable"
fi
if $MODLOAD_OK; then
  ok "module-loading-or-built-in satisfied ($MODLOAD_WHY)"
else
  fail "cannot load kernel modules (CONFIG_MODULES=$MODULES_CFG) and required features are not all built-in"
  GATE_FAILURES+=("CONFIG_MODULES: no module loading and netem/WireGuard not both built-in")
fi

if [[ ${#GATE_FAILURES[@]} -gt 0 ]]; then
  printf '\n%s################################################################%s\n' "$C_RED" "$C_RST"
  printf '%s# KERNEL GATE FAILED — this host cannot run the eval campaign. #%s\n' "$C_RED" "$C_RST"
  printf '%s################################################################%s\n' "$C_RED" "$C_RST"
  for f in "${GATE_FAILURES[@]}"; do fail "$f"; done
  cat >&2 <<EOF

The evaluation needs a kernel that supports tc netem AND kernel WireGuard,
either built in (CONFIG_NET_SCH_NETEM=y, CONFIG_WIREGUARD=y) or loadable
(CONFIG_MODULES=y with /lib/modules/$KERNEL_RELEASE present so sch_netem and
wireguard can be modprobe'd). Provision a VM / bare-metal host with a stock
distribution kernel; container "guest" kernels often strip these.
EOF
  exit 2
fi
ok "kernel gate PASSED"

# =============================================================================
# 3. Native liboqs
# =============================================================================
section "3. native liboqs"
if $SKIP_LIBOQS; then
  warn "skipping liboqs build (--skip-liboqs)"
else
  bash "$ROOT_DIR/scripts/install-liboqs.sh" "$LIBOQS_PREFIX"
  ok "native liboqs installed under $LIBOQS_PREFIX"
fi

# =============================================================================
# 4. Python venv + pinned dependencies
# =============================================================================
section "4. python environment"
if $SKIP_PYTHON; then
  warn "skipping venv/pip (--skip-python)"
else
  if [[ ! -x "$VENV_DIR/bin/python" ]]; then
    "$PYTHON_BIN" -m venv "$VENV_DIR"
    ok "created venv at $VENV_DIR (via $PYTHON_BIN)"
  else
    ok "reusing existing venv at $VENV_DIR"
  fi
  PY_FULL="$("$VENV_DIR/bin/python" -c 'import platform;print(platform.python_version())')"
  PY_SERIES="${PY_FULL%.*}"
  if [[ "$PY_SERIES" != "$TESTED_PY_SERIES" ]]; then
    warn "venv Python is $PY_FULL but constraints-tested.txt targets CPython ${TESTED_PY_SERIES}.x"
    warn "the pinned numpy/pandas/matplotlib versions likely will NOT resolve on $PY_SERIES."
    warn "install CPython ${TESTED_PY_SERIES} and re-run with --python, for a faithful reproduction."
  fi
  "$VENV_DIR/bin/pip" install --upgrade pip >/dev/null
  # Native liboqs is already installed, so liboqs-python loads it rather than
  # triggering its own download/build.
  OQS_INSTALL_PATH="$LIBOQS_PREFIX" "$VENV_DIR/bin/pip" install \
    -c "$ROOT_DIR/constraints-tested.txt" "$ROOT_DIR[dev]"
  ok "installed project + dev dependencies (pinned via constraints-tested.txt)"
fi

# =============================================================================
# 5. Native-liboqs runtime verification (NO measurement numbers)
# =============================================================================
section "5. native PQC verification"
if $SKIP_CRYPTO_VERIFY; then
  warn "skipping crypto verification (--skip-crypto-verify)"
else
  VPY="$VENV_DIR/bin/python"
  [[ -x "$VPY" ]] || VPY="python3"
  # Run from the repo root so `crypto` is importable; guard with `if` so a
  # non-zero exit is handled here rather than aborting under `set -e`.
  if ( cd "$ROOT_DIR" && OQS_INSTALL_PATH="$LIBOQS_PREFIX" "$VPY" - <<'PY'
import sys
from crypto.hybrid_crypto import get_crypto_status
status = get_crypto_status()
mode = status.get("pqc_mode")
print(f"  pqc_mode        = {mode}")
print(f"  liboqs_available= {status.get('liboqs_available')}")
print(f"  is_quantum_safe = {status.get('is_quantum_safe')}")
if status.get("load_error"):
    print(f"  load_error      = {status['load_error']}")
try:
    import oqs
    ver = oqs.oqs_version() if hasattr(oqs, "oqs_version") else getattr(oqs, "__version__", "?")
    print(f"  liboqs_version  = {ver}")
    print(f"  liboqs-python   = {oqs.oqs_python_version() if hasattr(oqs,'oqs_python_version') else '?'}")
except Exception as e:  # pragma: no cover
    print(f"  (could not query liboqs version: {e})")
if mode != "native_liboqs":
    sys.stderr.write("FATAL: pqc_mode is not native_liboqs — refusing to call this host ready.\n")
    sys.exit(1)
PY
  ); then
    ok "native liboqs active (pqc_mode == native_liboqs)"
  else
    fail "native liboqs verification FAILED"
    exit 1
  fi
fi

# =============================================================================
# Done
# =============================================================================
section "provisioning complete"
ok "host is ready for the PQ-VPN evaluation campaign"
echo
echo "Next (on THIS host, as root):"
echo "  sudo $VENV_DIR/bin/python -m pytest tests/ -q      # suite under native PQC"
echo "  sudo bash eval/run_pqvpn_net.sh lan --iterations 5 # Step 0 gate run"
