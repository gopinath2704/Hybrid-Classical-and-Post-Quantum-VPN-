# Linux packaging foundation

These files are an initial, reviewable packaging foundation for the PQ-VPN
research/prototype. They do not establish that either package has been installed
or live-validated.

Both distribution formats install the normal-user `pqvpn-gui` desktop launcher,
the Python application, icon, documentation, and a separately managed privileged
`pqvpn-client.service`. The service creates `/var/lib/pqvpn` with mode `0700` and
does not install a client private key, a trusted server profile, live deployment
configuration, or an authorized-client database.

Native ML-KEM is fail-closed. The Arch package metadata requires the PQ-VPN
liboqs and Python binding packages at exactly the currently validated `0.16.0`.
The Python package carries a checksum-verified downstream patch that removes the
upstream binding's runtime liboqs downloader, defaults its native prefix to `/usr`,
and prefers `/usr/lib` over generic loader discovery. No application runtime
download, mock fallback, hidden native copy, or unpinned native build is enabled.

## Arch / Omarchy

Build and install the dependencies in order from the repository root. These
commands acquire sources only during makepkg's source phase; neither package
performs a build-time or runtime download after that.

```bash
(cd packaging/arch/liboqs-pqvpn && makepkg --cleanbuild --syncdeps)
sudo pacman -U packaging/arch/liboqs-pqvpn/liboqs-pqvpn-0.16.0-1-x86_64.pkg.tar.zst

(cd packaging/arch/python-liboqs-pqvpn && makepkg --cleanbuild --syncdeps)
sudo pacman -U packaging/arch/python-liboqs-pqvpn/python-liboqs-pqvpn-0.16.0-1-any.pkg.tar.zst
PYTHONNOUSERSITE=1 OQS_INSTALL_PATH=/usr python - <<'PY'
from pathlib import Path
import oqs
assert oqs.oqs_python_version() == "0.16.0"
assert oqs.oqs_version() == "0.16.0"
assert "ML-KEM-768" in oqs.get_enabled_kem_mechanisms()
mapped = {line.split()[-1] for line in Path("/proc/self/maps").read_text().splitlines()
          if "/liboqs.so" in line}
assert mapped and all(path.startswith("/usr/lib/liboqs.so") for path in mapped), mapped
PY
```

`liboqs-pqvpn` uses the official liboqs commit archive for
`5a1a854b0dc9f2141bdc771c555ee60c37950183`:

```text
https://github.com/open-quantum-safe/liboqs/archive/5a1a854b0dc9f2141bdc771c555ee60c37950183.tar.gz
SHA-256 83c6e6cff490638312e1e20ed5de593fb5d7bfab162235f6238f519d6a1feafb
```

`python-liboqs-pqvpn` uses the official liboqs-python commit archive for the
`0.16.0` tag at `c6378cd5c8db74c0adf34ddcfbb96ee9c99f8061`:

```text
https://github.com/open-quantum-safe/liboqs-python/archive/c6378cd5c8db74c0adf34ddcfbb96ee9c99f8061.tar.gz
SHA-256 3de72cde836a72e4584dad6415a41610f980f924cae95a3848011fcb4f3a3b05
downstream patch SHA-256 0693b70ffa0a6475f018be369e614df99661b6643a2e6ffc6830b9f2087333b1
```

The private development branch has no release archive, so create the main
package source from the committed `HEAD` with this exact command. The allowlist
contains every source/build/install input consumed by `arch/PKGBUILD`, while
excluding the deployment-specific `config/client.toml`, all identities and live
state, tests, caches, untracked files, and the Arch PKGBUILD itself. Excluding the
PKGBUILD avoids making its checksum self-referential.

```bash
git archive --format=tar.gz --mtime=2026-09-14T00:00:00Z \
  --prefix=pqvpn-2.0.0/ \
  --output=packaging/arch/pqvpn-2.0.0.tar.gz 'HEAD^{tree}' -- \
  app benchmarks.py crypto handshake vpn pyproject.toml README.md \
  docs/design.md docs/deployment.md packaging/common
printf '%s  %s\n' \
  c8042bb8d576c5ffca0c762b1972899bd05b82848fbdab52cbb80f382e9ad043 \
  packaging/arch/pqvpn-2.0.0.tar.gz | sha256sum --check -
(cd packaging/arch && makepkg --cleanbuild --syncdeps)
```

Archiving `HEAD^{tree}` omits Git's commit-ID PAX header, and the fixed `--mtime`
makes the archive independent of the final commit timestamp. `git archive` reads
only committed objects and produces the required
`pqvpn-2.0.0/` top-level directory; it never copies `.git`, the working tree's
untracked keys, or user/system state. If a later commit changes any allowlisted
input, recreate the archive, run `(cd packaging/arch && updpkgsums)`, and review
and commit the resulting real checksum before building. Never substitute `SKIP`.
The packaged command launchers and privileged client service use Python's `-s`
mode, so an invoking user's `~/.local` site-packages cannot shadow the
Pacman-managed wrapper.

## Debian / Ubuntu 26.04-class

Ubuntu 26.04 does not provide the `python3-liboqs` and `liboqs0` dependency names
previously referenced by the main package. Build the two project-owned, exact-
version packages first; their metadata lives under `deb/liboqs-pqvpn` and
`deb/python3-liboqs-pqvpn`. They deliberately do not fetch source or native
libraries at build or run time.

Download the official commit archives separately and verify them before adding
the matching `debian` directory:

| package | pinned commit | archive SHA-256 |
| --- | --- | --- |
| liboqs 0.16.0 | `5a1a854b0dc9f2141bdc771c555ee60c37950183` | `83c6e6cff490638312e1e20ed5de593fb5d7bfab162235f6238f519d6a1feafb` |
| liboqs-python 0.16.0 | `c6378cd5c8db74c0adf34ddcfbb96ee9c99f8061` | `3de72cde836a72e4584dad6415a41610f980f924cae95a3848011fcb4f3a3b05` |

The Python wrapper also applies
`deb/python3-liboqs-pqvpn/debian/patches/disable-runtime-liboqs-download.patch`
with SHA-256
`0693b70ffa0a6475f018be369e614df99661b6643a2e6ffc6830b9f2087333b1`.
Build in this order with `dpkg-buildpackage --build=binary --no-sign`:

1. `liboqs-pqvpn_0.16.0-1_amd64.deb`
2. `python3-liboqs-pqvpn_0.16.0-1_all.deb`
3. `pqvpn_2.0.0-1_amd64.deb`

Install the first package before building the second, and both before building
the main package. The main build runs an explicit import check that requires
`native_liboqs`, so a mock or missing backend cannot produce a successful build.
Its Debian-only `use-debian-runtime-dependencies.patch` prevents upstream PyPI
pins from producing dependencies unavailable in Ubuntu; the complete runtime
set remains explicit in `deb/debian/control`.
Inspect the results with `dpkg-deb --info`, `dpkg-deb --contents`, and
`dpkg-deb --field`; then install all three together in a clean Ubuntu 26.04
environment and confirm `oqs.oqs_version()` and `oqs.oqs_python_version()` both
return `0.16.0` and `ML-KEM-768` is enabled.

The upstream PQ-VPN repository currently lacks a declared license, so
redistribution of these packages must remain blocked until the owner adds one.
