#!/usr/bin/env bash
# Explicit administrator-run build; never called by service startup or imports.
set -euo pipefail
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT
PREFIX=${1:-/usr/local}
[[ "$PREFIX" = /* ]] || { echo 'prefix must be absolute' >&2; exit 1; }
git clone --depth 1 --branch 0.16.0 https://github.com/open-quantum-safe/liboqs.git "$BUILD_DIR/liboqs"
cmake -S "$BUILD_DIR/liboqs" -B "$BUILD_DIR/build" -G Ninja \
  -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release -DOQS_BUILD_ONLY_LIB=ON \
  -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_INSTALL_PREFIX="$PREFIX"
cmake --build "$BUILD_DIR/build" --parallel 2
cmake --install "$BUILD_DIR/build"
ldconfig
