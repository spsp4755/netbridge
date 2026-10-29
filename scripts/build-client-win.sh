#!/usr/bin/env bash
# Quick Windows build of netbridge.exe only (for manual testing): target/docker/x86_64-pc-windows-gnu/release/netbridge.exe
set -euo pipefail
cd "$(dirname "$0")/.."
docker run --rm -u "$(id -u):$(id -g)" -e HOME=/tmp -e CARGO_HOME=/cargo -v "$PWD":/src -v "${CARGO_HOME:-$HOME/.cargo}/registry":/cargo/registry \
  -e CARGO_TARGET_DIR=/src/target/docker netbridge-winbuild:0.1 cargo build --release --locked --target x86_64-pc-windows-gnu -p netbridge-client
