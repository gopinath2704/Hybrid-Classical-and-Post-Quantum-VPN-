#!/usr/bin/env bash
# One-shot PQ-VPN server install on a fresh Ubuntu host (e.g. an AWS EC2 instance).
# Automates the "Install and provision" steps of docs/deployment.md; see docs/aws.md.
#
# Usage (root, from a clean checkout):
#   sudo bash scripts/deploy-server.sh                              # install only
#   sudo bash scripts/deploy-server.sh /tmp/alice_public.key alice  # + authorize, doctor, start
#
# Re-running is safe: an existing identity, server.toml and client database are kept.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'run as root (sudo)' >&2; exit 1; }
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLIENT_KEY=${1:-}; CLIENT_ID=${2:-}
[[ -z $CLIENT_KEY || -n $CLIENT_ID ]] || { echo 'usage: deploy-server.sh [client_public.key client_id]' >&2; exit 1; }
PY=/opt/pqvpn/.venv/bin/python

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
  --exclude=ENV --exclude=__pycache__ --exclude=.pytest_cache "$SRC/" /opt/pqvpn/
python3 -m venv /opt/pqvpn/.venv
"$PY" -m pip install -q -c /opt/pqvpn/constraints-tested.txt /opt/pqvpn
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
systemctl daemon-reload

if [[ -n $CLIENT_KEY ]]; then
  echo "== authorize client $CLIENT_ID"
  "$PY" -m vpn.cli client authorize "$CLIENT_KEY" --database /etc/pqvpn/authorized_clients.json --client-id "$CLIENT_ID"
  chown root:pqvpn /etc/pqvpn/authorized_clients.json; chmod 0640 /etc/pqvpn/authorized_clients.json
  echo '== doctor'
  sudo -u pqvpn "$PY" -m vpn.cli doctor server --config /etc/pqvpn/server.toml
  echo '== start'
  systemctl enable --now pqvpn-server
  systemctl --no-pager status pqvpn-server
fi

echo
echo "Server identity fingerprint: $(sha256sum /etc/pqvpn/server_identity_public.key | cut -d' ' -f1)"
echo 'Copy /etc/pqvpn/server_identity_public.key to each client (it is public; the private key never leaves this host).'
