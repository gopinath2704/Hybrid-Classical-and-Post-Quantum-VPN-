#!/usr/bin/env bash
# One-shot PQ-VPN desktop client install (Arch or Debian/Ubuntu).
#
# Usage (root, from a clean checkout):
#   sudo bash scripts/install-client.sh
#
# Installs liboqs, /opt/pqvpn with a venv (GUI extra), the privileged pqvpn-client
# service, and a pqvpn-gui launcher. Re-running upgrades in place; device identity
# and managed state under /var/lib/pqvpn are kept. Registration needs an admin invite code.
set -euo pipefail
[[ $EUID -eq 0 ]] || { echo 'run as root (sudo)' >&2; exit 1; }
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY=/opt/pqvpn/.venv/bin/python

echo '== OS packages'
if command -v pacman >/dev/null; then
  pacman -S --needed --noconfirm python git cmake ninja base-devel openssl iproute2 nftables rsync
elif command -v apt-get >/dev/null; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -q
  apt-get install -yq python3 python3-venv git cmake ninja-build build-essential libssl-dev \
    iproute2 nftables rsync libgl1 libxkbcommon-x11-0 libegl1 libdbus-1-3
else
  echo 'unsupported distro: need pacman or apt-get' >&2; exit 1
fi
python3 -c 'import sys; assert sys.version_info >= (3, 11), "Python 3.11+ required"'
test -c /dev/net/tun || { echo '/dev/net/tun missing (modprobe tun)' >&2; exit 1; }

echo '== native liboqs'
ldconfig -p | grep -q 'liboqs\.so' || bash "$SRC/scripts/install-liboqs.sh" /usr/local

echo '== /opt/pqvpn (root-owned)'
install -d -o root -g root -m 0755 /opt/pqvpn
rsync -a --delete --chown=root:root --exclude=.git --exclude=.venv --exclude=venv --exclude=env \
  --exclude=ENV --exclude=__pycache__ --exclude=.pytest_cache --exclude='config/*.key' \
  --exclude=config/client.toml "$SRC/" /opt/pqvpn/
rm -rf /opt/pqvpn/build /opt/pqvpn/dist /opt/pqvpn/*.egg-info
python3 -m venv /opt/pqvpn/.venv
"$PY" -m pip install -q -c /opt/pqvpn/constraints-tested.txt '/opt/pqvpn[desktop]'
chown -R root:root /opt/pqvpn
chmod -R u=rwX,go=rX /opt/pqvpn

echo '== service and launcher'
cd /opt/pqvpn
install -m 0644 packaging/common/pqvpn-client-deploy.service /etc/systemd/system/pqvpn-client.service
# The service only accepts IPC from root and PQVPN_ALLOWED_UIDS, so authorize the invoking desktop user.
if [[ ${SUDO_UID:-} =~ ^[1-9][0-9]*$ ]]; then
  install -d -m 0755 /etc/systemd/system/pqvpn-client.service.d
  printf '[Service]\nEnvironment=PQVPN_ALLOWED_UIDS=%s\n' "$SUDO_UID" \
    > /etc/systemd/system/pqvpn-client.service.d/allowed-uids.conf
else
  echo 'warning: not run via sudo; set PQVPN_ALLOWED_UIDS in a pqvpn-client drop-in or the GUI is refused' >&2
fi
install -Dm644 packaging/common/pqvpn.desktop /usr/share/applications/pqvpn.desktop
install -Dm644 packaging/common/pqvpn.svg /usr/share/icons/hicolor/scalable/apps/pqvpn.svg
ln -sf /opt/pqvpn/.venv/bin/pqvpn-gui /usr/local/bin/pqvpn-gui
systemctl daemon-reload
systemctl enable pqvpn-client.service
systemctl restart pqvpn-client.service
sleep 1
systemctl is-active --quiet pqvpn-client.service || { journalctl -u pqvpn-client -n 20 --no-pager; exit 1; }

echo 'Done. Launch "pqvpn-gui" (or PQ-VPN from the app menu), register with your invite code, then Connect.'
