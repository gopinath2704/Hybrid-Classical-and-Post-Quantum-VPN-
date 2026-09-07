#!/usr/bin/env bash
# Explicit administrator-run build; never called by service startup or imports.
set -euo pipefail
LIBOQS_VERSION=0.16.0
LIBOQS_COMMIT=5a1a854b0dc9f2141bdc771c555ee60c37950183
BUILD_DIR=$(mktemp -d)
trap 'rm -rf "$BUILD_DIR"' EXIT
PREFIX=${1:-/usr/local}
[[ "$PREFIX" = /* ]] || { echo 'prefix must be absolute' >&2; exit 1; }
git clone --depth 1 --branch "$LIBOQS_VERSION" https://github.com/open-quantum-safe/liboqs.git "$BUILD_DIR/liboqs"
ACTUAL=$(git -C "$BUILD_DIR/liboqs" rev-parse HEAD)
if [[ "$ACTUAL" != "$LIBOQS_COMMIT" ]]; then
  echo "liboqs source mismatch: expected $LIBOQS_COMMIT, got $ACTUAL" >&2
  exit 1
fi
echo "Building liboqs $LIBOQS_VERSION at verified source $ACTUAL"
cmake -S "$BUILD_DIR/liboqs" -B "$BUILD_DIR/build" -G Ninja \
  -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release -DOQS_BUILD_ONLY_LIB=ON \
  -DCMAKE_INSTALL_LIBDIR=lib -DCMAKE_INSTALL_PREFIX="$PREFIX"
cmake --build "$BUILD_DIR/build" --parallel 2
cmake --install "$BUILD_DIR/build"
ldconfig
