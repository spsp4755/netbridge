#!/usr/bin/env bash
# Packs the source with all crate dependencies for building inside the closed network:
#   tar xzf netbridge-src-vendored.tar.gz && cd netbridge && cargo build --release --offline
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p .cargo dist
cargo vendor --locked vendor > .cargo/config.toml
tar czf dist/netbridge-src-vendored.tar.gz --exclude=./target --exclude=./dist --exclude=./.git --transform 's,^\.,netbridge,' .
rm -rf vendor .cargo/config.toml
echo "dist/netbridge-src-vendored.tar.gz"
