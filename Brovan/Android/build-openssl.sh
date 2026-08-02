#!/usr/bin/env bash
# Builds libssl/libcrypto for android-arm64 into the directory build-apk.sh picks them up from.
#
# .NET aborts the process on the first OpenSSL-backed primitive ("No usable version of libssl was found") and
# Android exposes no libssl to apps. OpenSSL's android targets emit unversioned sonames, which is both what
# Android packaging allows and what .NET's probe list accepts.
set -euo pipefail

TOOLS="${BROVAN_TOOLCHAIN:-$HOME/brovan-toolchain}"
VERSION="${OPENSSL_VERSION:-3.5.4}"
OUT="${OPENSSL_BUILD:-$TOOLS/openssl-$VERSION}"
API_LEVEL="${API_LEVEL:-26}"
SRC="$TOOLS/src/openssl-$VERSION"

export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$TOOLS/android-sdk}"
NDK="${ANDROID_NDK_HOME:-$(ls -d "$ANDROID_SDK_ROOT"/ndk/* 2>/dev/null | sort -V | tail -1)}"
[ -n "$NDK" ] && [ -d "$NDK" ] || { echo "Android NDK not found under $ANDROID_SDK_ROOT/ndk" >&2; exit 1; }

if [ -f "$OUT/libssl.so" ] && [ -f "$OUT/libcrypto.so" ]; then
    echo "OpenSSL $VERSION already built at $OUT"
    exit 0
fi

mkdir -p "$TOOLS/src"
if [ ! -f "$SRC/Configure" ]; then
    curl -fsSL "https://github.com/openssl/openssl/releases/download/openssl-$VERSION/openssl-$VERSION.tar.gz" \
        -o "$TOOLS/src/openssl-$VERSION.tar.gz"
    tar -xzf "$TOOLS/src/openssl-$VERSION.tar.gz" -C "$TOOLS/src"
fi

export ANDROID_NDK_ROOT="$NDK"
export PATH="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin:$PATH"

cd "$SRC"
# Android 16 shows PageSizeMismatchDialog for 4K-aligned libraries and 16K-page devices refuse them.
./Configure android-arm64 -D__ANDROID_API__="$API_LEVEL" shared no-tests no-docs \
    -Wl,-z,max-page-size=16384
make -j"$(nproc)" build_libs

mkdir -p "$OUT"
cp "$SRC/libssl.so" "$SRC/libcrypto.so" "$OUT/"
echo "OpenSSL $VERSION -> $OUT"
