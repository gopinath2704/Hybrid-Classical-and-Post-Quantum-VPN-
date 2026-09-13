# Linux packaging foundation

These files are an initial, reviewable packaging foundation for the PQ-VPN
research/prototype. They do not establish that either package has been installed
or live-validated.

Both packages install the normal-user `pqvpn-gui` desktop launcher, the Python
application, icon, documentation, and a separately managed privileged
`pqvpn-client.service`. The service creates `/var/lib/pqvpn` with mode `0700` and
does not install a client private key, a trusted server profile, live deployment
configuration, or an authorized-client database.

Native ML-KEM is fail-closed. The package metadata requires liboqs and its Python
binding at exactly the currently validated `0.16.0`; distributors must make those
packages available. No application runtime download, mock fallback, or unpinned
native build is enabled.

## Arch / Omarchy

Create a reviewed `pqvpn-2.0.0.tar.gz` source archive, replace
`REPLACE_WITH_RELEASE_ARCHIVE_SHA256` in `arch/PKGBUILD` with its real SHA-256,
then run `makepkg --cleanbuild --syncdeps`. The placeholder deliberately prevents
an unverified build.

## Debian / Ubuntu 26.04-class

Copy `deb/debian` to the source archive as `debian`, verify that the exact liboqs
0.16.0 packages are available from the chosen trusted repository, and run
`dpkg-buildpackage --build=binary --no-sign`. The upstream repository currently
lacks a declared license, so redistribution must remain blocked until the owner
adds one.
