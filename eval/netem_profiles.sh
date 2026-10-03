#!/usr/bin/env bash
# Shared network-profile table and helpers for the evaluation campaign.
#
# Every baseline runner (run_wireguard.sh, run_rosenpass.sh,
# run_strongswan.sh) sources this file so that all systems are measured over
# the SAME netns + veth + tc-netem topology and the SAME six profiles as
# run_pqvpn_net.sh. The values below MUST stay identical to the inline table
# in eval/run_pqvpn_net.sh.
#
# Profiles:
#   lan       rtt   0ms  loss 0%  mtu 1500
#   metro     rtt  50ms  loss 0%  mtu 1500
#   continent rtt 200ms  loss 0%  mtu 1500
#   lossy-1   rtt  50ms  loss 1%  mtu 1500
#   lossy-5   rtt  50ms  loss 5%  mtu 1500
#   mtu-1280  rtt  50ms  loss 0%  mtu 1280
#
# netem is applied symmetrically on BOTH veth endpoints with delay = rtt/2,
# so the round-trip time observed by the application equals rtt.

# shellcheck disable=SC2034
declare -A NETEM_RTT_MS NETEM_LOSS_PCT NETEM_LINK_MTU
NETEM_RTT_MS=(   [lan]=0    [metro]=50   [continent]=200  [lossy-1]=50   [lossy-5]=50   [mtu-1280]=50   )
NETEM_LOSS_PCT=( [lan]=0    [metro]=0    [continent]=0    [lossy-1]=1    [lossy-5]=5    [mtu-1280]=0    )
NETEM_LINK_MTU=( [lan]=1500 [metro]=1500 [continent]=1500 [lossy-1]=1500 [lossy-5]=1500 [mtu-1280]=1280 )

NETEM_PROFILES="lan metro continent lossy-1 lossy-5 mtu-1280"

# netem_profile_valid <profile> -> exit 0 if known, else 1
netem_profile_valid() {
  [[ -n "${NETEM_RTT_MS[$1]+x}" ]]
}

# netem_rtt / netem_loss / netem_mtu / netem_delay_each — accessors
netem_rtt()        { echo "${NETEM_RTT_MS[$1]}"; }
netem_loss()       { echo "${NETEM_LOSS_PCT[$1]}"; }
netem_mtu()        { echo "${NETEM_LINK_MTU[$1]}"; }
netem_delay_each() { echo "$(( ${NETEM_RTT_MS[$1]} / 2 ))"; }

# netem_apply <netns> <dev> <profile>
# Applies the profile's delay+loss to <dev> inside <netns>. No-op when the
# profile has neither delay nor loss (e.g. lan), so the qdisc stays default.
netem_apply() {
  local ns=$1 dev=$2 profile=$3
  local delay_each loss
  delay_each=$(netem_delay_each "$profile")
  loss=$(netem_loss "$profile")
  if (( delay_each > 0 )) || (( loss > 0 )); then
    local args="delay ${delay_each}ms"
    if (( loss > 0 )); then
      args="$args loss ${loss}%"
    fi
    # shellcheck disable=SC2086
    ip netns exec "$ns" tc qdisc add dev "$dev" root netem $args
  fi
}

# netem_require_tools — fail fast if the topology tools are missing, so a
# profile is never silently skipped (which would flatten a metric across
# profiles and look like "netem was not applied").
netem_require_tools() {
  local missing=()
  command -v ip >/dev/null 2>&1 || missing+=(ip)
  command -v tc >/dev/null 2>&1 || missing+=(tc)
  if (( ${#missing[@]} )); then
    echo "ERROR: missing required tools: ${missing[*]} (install iproute2)" >&2
    return 1
  fi
}

# eval_provenance_fields — print the 5 metadata values as a comma-tail
# (git_commit,liboqs_version,cpu_model,governor,kernel) so every CSV row can
# carry its own provenance. ROOT_DIR must be set by the caller.
eval_provenance_fields() {
  local root="${ROOT_DIR:-.}"
  local commit liboqs cpu gov kernel
  commit=$(git -C "$root" rev-parse --short HEAD 2>/dev/null || echo unknown)
  liboqs=$(python3 -c "import oqs; print(oqs.oqs_version() if hasattr(oqs,'oqs_version') else getattr(oqs,'__version__','available'))" 2>/dev/null || echo unknown)
  cpu=$(grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2 | sed 's/^ *//;s/,/ /g' || echo unknown)
  [[ -z "$cpu" ]] && cpu=unknown
  gov=$(cat /sys/devices/system/cpu/cpu0/cpufreq/scaling_governor 2>/dev/null || echo unknown)
  kernel=$(uname -r 2>/dev/null || echo unknown)
  echo "${commit},${liboqs},${cpu},${gov},${kernel}"
}

# Extended unified CSV header (6 core columns + 5 provenance columns).
# generate_tables.py keys only off the 6 core columns and tolerates the
# trailing provenance columns (its reader accepts any superset).
EVAL_CSV_HEADER="system,profile,metric,run,value,unit,git_commit,liboqs_version,cpu_model,governor,kernel"
