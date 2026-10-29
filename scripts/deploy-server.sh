#!/usr/bin/env bash
# One-shot PQ-VPN server install on a fresh Ubuntu host (e.g. an AWS EC2 instance).
# Automates the "Install and provision" steps of docs/deployment.md; see docs/aws.md.
#
# Usage (root, from a clean checkout):
#   sudo bash scripts/deploy-server.sh                              # install only
#   sudo bash scripts/deploy-server.sh /tmp/alice_public.key alice  # + authorize, doctor, start
#   sudo env PQVPN_DATA_PLANE=rust bash scripts/deploy-server.sh    # build core/, set data_plane (or =python)
#
# Re-running is safe: an existing identity, server.toml and client database are kept;
# a legacy /etc/pqvpn/authorized_clients.json is migrated to /var/lib/pqvpn/authorized/.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'run as root (sudo)' >&2; exit 1; }
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLIENT_KEY=${1:-}; CLIENT_ID=${2:-}
[[ -z $CLIENT_KEY || -n $CLIENT_ID ]] || { echo 'usage: deploy-server.sh [client_public.key client_id]' >&2; exit 1; }
PY=/opt/pqvpn/.venv/bin/python
DATA_PLANE=${PQVPN_DATA_PLANE:-}
[[ $DATA_PLANE =~ ^(|python|rust)$ ]] || { echo 'PQVPN_DATA_PLANE must be python or rust' >&2; exit 1; }

echo '== OS packages'
export DEBIAN_FRONTEND=noninteractive
apt-get update -q
apt-get install -yq python3 python3-venv git cmake ninja-build build-essential libssl-dev \
  iproute2 nftables util-linux rsync procps
python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required"'
python3 -c 'import sys; sys.version_info[:2] == (3, 14) or print("WARN: tested baseline is CPython 3.14; this is", sys.version.split()[0])'
test -c /dev/net/tun || { echo '/dev/net/tun missing' >&2; exit 1; }

echo '== native liboqs'
ldconfig -p | grep -q 'liboqs\.so' || bash "$SRC/scripts/install-liboqs.sh" /usr/local

echo '== /opt/pqvpn (root-owned) and /etc/pqvpn'
id pqvpn >/dev/null 2>&1 || useradd --system --home /opt/pqvpn --shell /usr/sbin/nologin pqvpn
install -d -o root -g root -m 0755 /opt/pqvpn
install -d -o root -g pqvpn -m 0750 /etc/pqvpn
rsync -a --delete --chown=root:root --exclude=.git --exclude=.venv --exclude=venv --exclude=env \
  --exclude=ENV --exclude=__pycache__ --exclude=.pytest_cache --exclude=target "$SRC/" /opt/pqvpn/
python3 -m venv /opt/pqvpn/.venv
"$PY" -m pip install -q -c /opt/pqvpn/constraints-tested.txt /opt/pqvpn
# Rebuild the Rust core on every deploy of a Rust server so it never lags the Python code;
# PQVPN_DATA_PLANE=python skips it so a rollback never depends on cargo.
if [[ $DATA_PLANE == rust ]] || { [[ -z $DATA_PLANE ]] && grep -Eq '^[[:space:]]*data_plane[[:space:]]*=[[:space:]]*"rust"' /etc/pqvpn/server.toml 2>/dev/null; }; then
  echo '== Rust core (pqvpn_core)'
  export PATH=/root/.cargo/bin:$PATH RUSTUP_HOME=/root/.rustup CARGO_HOME=/root/.cargo
  command -v cargo >/dev/null || { echo 'cargo missing: install rustup for root (docs/deployment.md, Rust data plane)' >&2; exit 1; }
  "$PY" -m pip install --no-deps --force-reinstall --config-settings=build-args=--locked /opt/pqvpn/core/pqvpn_core
fi
chown -R root:root /opt/pqvpn
chmod -R u=rwX,go=rX /opt/pqvpn
cd /opt/pqvpn

if [[ ! -f /etc/pqvpn/server_identity_private.key ]]; then
  echo '== server identity'
  "$PY" -m vpn.cli identity generate --private /etc/pqvpn/server_identity_private.key \
    --public /etc/pqvpn/server_identity_public.key
fi
chown pqvpn:root /etc/pqvpn/server_identity_private.key; chmod 0400 /etc/pqvpn/server_identity_private.key
chown root:pqvpn /etc/pqvpn/server_identity_public.key; chmod 0640 /etc/pqvpn/server_identity_public.key
[[ -f /etc/pqvpn/server.toml ]] || install -o root -g pqvpn -m 0640 config/server.toml /etc/pqvpn/server.toml
install -m 0644 packaging/common/pqvpn-server.service /etc/systemd/system/pqvpn-server.service

echo '== authorized clients database'
# Own directory, root:pqvpn 2770: the lock and atomic-rename temp files need a
# group-writable directory, while /etc/pqvpn stays read-only for pqvpn-account
# (it holds the server private key). The VPN server only reads it (ProtectSystem=strict).
OLD_DB=/etc/pqvpn/authorized_clients.json
AUTH_DIR=/var/lib/pqvpn/authorized; AUTH_DB=$AUTH_DIR/authorized_clients.json
STAMP=$(date +%Y%m%d%H%M%S); RESTART=
[[ -d /var/lib/pqvpn ]] || install -d -o root -g root -m 0755 /var/lib/pqvpn
install -d -o root -g pqvpn -m 2770 "$AUTH_DIR"
valid_db() { "$PY" -c 'import sys; from pathlib import Path; from vpn.identity import AuthorizedClients
AuthorizedClients(Path(sys.argv[1]))._load(required=True)' "$1"; }
[[ ! -L $OLD_DB ]] || { echo "$OLD_DB is a symlink; migrate it by hand" >&2; exit 1; }
if [[ -f $OLD_DB ]]; then
  echo "== migrate $OLD_DB -> $AUTH_DB"
  systemctl stop pqvpn-account-api 2>/dev/null || true
  [[ ! -s $OLD_DB ]] || valid_db "$OLD_DB"
  if [[ -e $AUTH_DB || -L $AUTH_DB ]] && [[ -s $OLD_DB ]] && ! cmp -s "$OLD_DB" "$AUTH_DB"; then
    echo "$OLD_DB and $AUTH_DB both exist and differ; reconcile by hand" >&2; exit 1
  fi
fi
if [[ ! -e $AUTH_DB && ! -L $AUTH_DB ]]; then
  # Stage in a root-only directory, then rename in: group members can swap
  # entries inside AUTH_DIR, so root never chowns/chmods a path there.
  STAGE=$(mktemp -d /var/lib/pqvpn/.authorized-stage.XXXXXX)
  if [[ -s $OLD_DB ]]; then cat "$OLD_DB"; else echo '{"clients": []}'; fi > "$STAGE/db"
  chown root:pqvpn "$STAGE/db"; chmod 0640 "$STAGE/db"
  mv -T "$STAGE/db" "$AUTH_DB"; rmdir "$STAGE"
fi
if [[ -f $OLD_DB ]]; then
  BAK=$OLD_DB.migrated; [[ ! -e $BAK ]] || BAK+=.$STAMP
  chown root:root "$OLD_DB"; chmod 0600 "$OLD_DB"; mv -T "$OLD_DB" "$BAK"
  rm -f "$OLD_DB.lock"; RESTART=1
  echo "old database kept as $BAK (root-only)"
fi
valid_db "$AUTH_DB"
# Repoint configs that still name the old database (relative or absolute); keep a backup.
retarget() {
  local re='^([[:space:]]*authorized_clients_file[[:space:]]*=[[:space:]]*)"(/etc/pqvpn/)?authorized_clients\.json"'
  [[ -f $1 ]] && grep -Eq "$re" "$1" || return 0
  cp -p "$1" "$1.bak.$STAMP"
  sed -E -i "s#$re#\1\"$AUTH_DB\"#" "$1"
  RESTART=1; echo "repointed $1 (backup $1.bak.$STAMP)"
}
retarget /etc/pqvpn/server.toml
if [[ -n $DATA_PLANE ]] && ! grep -Eq "^data_plane = \"$DATA_PLANE\"\$" /etc/pqvpn/server.toml; then
  cp -p /etc/pqvpn/server.toml "/etc/pqvpn/server.toml.bak.$STAMP"
  if grep -Eq '^[[:space:]]*data_plane[[:space:]]*=' /etc/pqvpn/server.toml; then
    sed -E -i "s/^[[:space:]]*data_plane[[:space:]]*=.*/data_plane = \"$DATA_PLANE\"/" /etc/pqvpn/server.toml
  else
    sed -i "/^\[server\]/a data_plane = \"$DATA_PLANE\"" /etc/pqvpn/server.toml
  fi
  RESTART=1; echo "data_plane = \"$DATA_PLANE\" (backup /etc/pqvpn/server.toml.bak.$STAMP)"
fi
[[ -z $DATA_PLANE ]] || "$PY" -c 'import sys; from vpn.config import load_server_config as load
sys.exit(f"data_plane is not {sys.argv[2]} in {sys.argv[1]}" if load(sys.argv[1]).data_plane != sys.argv[2] else 0)' \
  /etc/pqvpn/server.toml "$DATA_PLANE"

echo '== account API setup'
id pqvpn-account >/dev/null 2>&1 || useradd --system --home /nonexistent --shell /usr/sbin/nologin pqvpn-account
usermod -aG pqvpn pqvpn-account
# PQVPN_PUBLIC_HOST (IP or DNS name clients connect to) goes into the cert SAN; a cert
# that does not cover it is regenerated, so clients must re-fetch account-api.crt
# (and the default server's copy bundled as app/server-account-api.crt must be replaced).
SAN=DNS:pqvpn-account-api; CHECK=()
if [[ -n ${PQVPN_PUBLIC_HOST:-} ]]; then
  [[ $PQVPN_PUBLIC_HOST =~ ^[A-Za-z0-9.:-]+$ ]] || { echo 'invalid PQVPN_PUBLIC_HOST' >&2; exit 1; }
  if [[ $PQVPN_PUBLIC_HOST =~ ^[0-9.]+$|: ]]; then
    SAN+=",IP:$PQVPN_PUBLIC_HOST"; CHECK=(-checkip "$PQVPN_PUBLIC_HOST")
  else
    SAN+=",DNS:$PQVPN_PUBLIC_HOST"; CHECK=(-checkhost "$PQVPN_PUBLIC_HOST")
  fi
fi
CRT=/etc/pqvpn/tls/account-api.crt
if [[ ! -f $CRT ]] || { ((${#CHECK[@]})) && [[ $(openssl x509 -in "$CRT" -noout "${CHECK[@]}") != *' does match'* ]]; }; then
  echo "== account API TLS certificate ($SAN)"
  install -d -o root -g pqvpn-account -m 0750 /etc/pqvpn/tls
  openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -keyout /etc/pqvpn/tls/account-api.key -out "$CRT" \
    -days 3650 -nodes -subj "/CN=pqvpn-account-api" -addext "subjectAltName=$SAN"
  chown pqvpn-account:pqvpn-account /etc/pqvpn/tls/account-api.key
  chmod 0400 /etc/pqvpn/tls/account-api.key
  chown root:pqvpn-account /etc/pqvpn/tls/account-api.crt
  chmod 0644 /etc/pqvpn/tls/account-api.crt
fi
[[ -f /etc/pqvpn/account-api.toml ]] || install -o root -g pqvpn-account -m 0640 config/account-api.toml /etc/pqvpn/account-api.toml
retarget /etc/pqvpn/account-api.toml
# Fail closed if either service would still read another database (e.g. an omitted
# server.toml field resolves beside the TOML, i.e. the old path).
"$PY" -c 'import sys
from vpn.config import load_server_config
from vpn.account_api import load_account_api_config
want = sys.argv[1]
got = {"server.toml": load_server_config("/etc/pqvpn/server.toml").authorized_clients_file,
       "account-api.toml": str(load_account_api_config("/etc/pqvpn/account-api.toml").authorized_clients_file)}
bad = [f"{k} -> {v}" for k, v in got.items() if v != want]
sys.exit(f"set authorized_clients_file = \"{want}\" in: " + ", ".join(bad) if bad else 0)' "$AUTH_DB"
install -m 0644 packaging/common/pqvpn-account-api.service /etc/systemd/system/pqvpn-account-api.service
systemctl daemon-reload
systemctl enable pqvpn-account-api
# Always restart so updated code (and account DB schema migrations) take effect; no tunnels drop.
systemctl restart pqvpn-account-api
[[ -z $RESTART ]] || systemctl try-restart pqvpn-server

if [[ -n $CLIENT_KEY ]]; then
  echo "== authorize client $CLIENT_ID"
  # Writes root:pqvpn 0640 (directory group) itself; no chown/chmod inside AUTH_DIR.
  "$PY" -m vpn.cli client authorize "$CLIENT_KEY" --database "$AUTH_DB" --client-id "$CLIENT_ID"
  echo '== doctor'
  sudo -u pqvpn "$PY" -m vpn.cli doctor server --config /etc/pqvpn/server.toml
  echo '== start'
  systemctl enable --now pqvpn-server
  systemctl --no-pager status pqvpn-server
fi

echo
echo "Server identity fingerprint: $(sha256sum /etc/pqvpn/server_identity_public.key | cut -d' ' -f1)"
echo "Account API listening on port 8443 (HTTPS) with auto-approve enabled."
echo 'Clients can register at https://<server-ip>:8443 — no manual key copying needed.'
