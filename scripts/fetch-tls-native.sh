#!/bin/bash
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p toolchain
cd toolchain
GOST_COMMIT=af2b7e69e855572202420ffc36bae06ccd70796b
OPENSSL_SHA256=603f5602e2eef00d77fbd429d34dcd5822bb301757a1bc9cdb24c670f1eb859a
if [ ! -d gost-engine ]; then
 git init gost-engine
 git -C gost-engine remote add origin https://github.com/gost-engine/engine.git
 git -C gost-engine fetch --depth 1 origin "$GOST_COMMIT"
 git -C gost-engine checkout --detach "$GOST_COMMIT"
 git -C gost-engine submodule update --init --recursive --depth 1
fi
test "$(git -C gost-engine rev-parse HEAD)" = "$GOST_COMMIT"
if [ ! -f openssl-3.5.9.tar.gz ]; then
 curl -fL --connect-timeout 15 --max-time 120 --retry 2 -o openssl-3.5.9.tar.gz.part https://www.openssl.org/source/openssl-3.5.9.tar.gz
 mv openssl-3.5.9.tar.gz.part openssl-3.5.9.tar.gz
fi
printf '%s  openssl-3.5.9.tar.gz\n' "$OPENSSL_SHA256" | sha256sum -c -
if [ ! -d openssl-3.5.9 ]; then tar xzf openssl-3.5.9.tar.gz; fi
