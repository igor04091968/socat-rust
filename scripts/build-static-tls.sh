#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
export OPENSSL_DIR="$PWD/toolchain/linux-musl" OPENSSL_STATIC=1
export GOST_STATIC_LIB_DIR="$OPENSSL_DIR/lib"
export CC_x86_64_unknown_linux_musl=musl-gcc CARGO_BUILD_JOBS=2
export RUSTFLAGS='-C target-feature=+crt-static'
mkdir -p artifacts
for variant in plain tls tls-gost; do
  flags=(--no-default-features)
  suffix=
  if [ "$variant" != plain ]; then flags+=(--features "$variant"); suffix="-$variant"; fi
  nice -n 10 cargo test --locked --target x86_64-unknown-linux-musl "${flags[@]}"
  nice -n 10 cargo build --locked --release --target x86_64-unknown-linux-musl "${flags[@]}"
  binary="artifacts/socat-rust-linux-amd64${suffix}-static"
  cp target/x86_64-unknown-linux-musl/release/socat-rust "$binary"
  if readelf -l "$binary" | grep -q INTERP || readelf -d "$binary" | grep -q NEEDED; then
    echo "ERROR: binary has runtime library dependencies: $binary" >&2; exit 1
  fi
  file "$binary"
done
musl-gcc -O2 -static -Wno-deprecated-declarations -I"$OPENSSL_DIR/include" tests/gost_fixture.c -L"$OPENSSL_DIR/lib" -Wl,--start-group -lgost -lssl -lcrypto -Wl,--end-group -lpthread -o artifacts/gost-fixture
python3 scripts/test_tls_integration.py --binary artifacts/socat-rust-linux-amd64-tls-gost-static --plain-binary artifacts/socat-rust-linux-amd64-static --gost-fixture artifacts/gost-fixture --results artifacts/integration.json
