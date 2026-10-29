#!/usr/bin/env bash
# Builds dist/: Windows client installer, Windows and Linux server packages.
# Needs Docker; everything else runs inside build/Dockerfile.windows.
set -euo pipefail
cd "$(dirname "$0")/.."
VERSION=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
IMAGE=netbridge-winbuild:0.1
docker image inspect "$IMAGE" >/dev/null 2>&1 || docker build -t "$IMAGE" -f build/Dockerfile.windows build
mkdir -p dist
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e CARGO_HOME=/cargo \
  -v "$PWD":/src -v "${CARGO_HOME:-$HOME/.cargo}/registry":/cargo/registry \
  -e CARGO_TARGET_DIR=/src/target/docker \
  "$IMAGE" bash -euo pipefail -c "
    cargo build --release --locked --target x86_64-pc-windows-gnu -p netbridge-client -p netbridge-server
    cargo build --release --locked -p netbridge-server
    W=target/docker/x86_64-pc-windows-gnu/release
    rm -rf dist/win dist/server-win dist/server-linux && mkdir -p dist/win dist/server-win/certs dist/server-linux/certs
    cp \$W/netbridge.exe dist/win/
    find target/docker/x86_64-pc-windows-gnu/release/build -name netbridge.ico -path '*netbridge-client*' -exec cp {} dist/netbridge.ico \;
    (cd installer && makensis -V2 -DVERSION=$VERSION netbridge.nsi)
    for d in server-win server-linux; do cp deploy/external.toml deploy/internal.toml deploy/README-server.txt dist/\$d/; done
    cp \$W/netbridge-server.exe dist/server-win/
    cp target/docker/release/netbridge-server dist/server-linux/
    (cd dist && rm -f *.zip && zip -qr netbridge-server-$VERSION-windows.zip server-win && zip -qr netbridge-server-$VERSION-linux.zip server-linux)
  "
ls -la dist
