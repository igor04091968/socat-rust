#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
TASK_ROOT=$PWD
TLS_PREFIX=$TASK_ROOT/toolchain/linux-musl
mkdir -p toolchain/build-openssl-musl "$TLS_PREFIX" toolchain/kernel-uapi
cp -a /usr/include/linux /usr/include/asm-generic toolchain/kernel-uapi/
cp -a /usr/include/x86_64-linux-gnu/asm toolchain/kernel-uapi/
dpkg-query -W linux-libc-dev > toolchain/kernel-uapi.origin
cd toolchain/build-openssl-musl
CC=musl-gcc CFLAGS="-I$TASK_ROOT/toolchain/kernel-uapi" ../openssl-3.5.9/Configure linux-x86_64 no-shared no-dso no-tests no-zlib --prefix="$TLS_PREFIX" --libdir=lib
nice -n 10 make -j2
make install_sw
cd "$TASK_ROOT"
cmake -S toolchain/gost-engine -B toolchain/build-gost-musl -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER=musl-gcc -DCMAKE_EXE_LINKER_FLAGS=-static -DOPENSSL_ROOT_DIR="$TLS_PREFIX" -DOPENSSL_INCLUDE_DIR="$TLS_PREFIX/include" -DOPENSSL_CRYPTO_LIBRARY="$TLS_PREFIX/lib/libcrypto.a" -DOPENSSL_SSL_LIBRARY="$TLS_PREFIX/lib/libssl.a" -DOPENSSL_USE_STATIC_LIBS=TRUE -DOPENSSL_ENGINES_DIR="$TLS_PREFIX/lib/engines-3" -DGOST_BUILD_ENGINE=OFF -DGOST_BUILD_STATIC_ENGINE=ON -DGOST_BUILD_PROVIDER=OFF
nice -n 10 cmake --build toolchain/build-gost-musl --target gost_engine_static -j2
install -m 644 toolchain/build-gost-musl/libgost.a "$TLS_PREFIX/lib/libgost.a"
"$TLS_PREFIX/bin/openssl" version
file "$TLS_PREFIX/bin/openssl"
