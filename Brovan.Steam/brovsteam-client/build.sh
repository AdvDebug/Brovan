#!/bin/sh
set -eu

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
REPO="$(cd "$SCRIPT_DIR/../.." && pwd)"
CC="${CC:-x86_64-w64-mingw32-gcc}"

if ! command -v "$CC" >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        export DEBIAN_FRONTEND=noninteractive
        if [ "$(id -u)" -eq 0 ]; then
            apt-get update
            apt-get install -y mingw-w64
        elif command -v sudo >/dev/null 2>&1; then
            sudo apt-get update
            sudo apt-get install -y mingw-w64
        else
            echo "error: '$CC' not found and sudo is unavailable to install mingw-w64." >&2
            exit 1
        fi
    fi
fi

if ! command -v "$CC" >/dev/null 2>&1; then
    echo "error: MinGW-w64 compiler '$CC' not found on PATH. Install mingw-w64 or set CC." >&2
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/obj/generated/brovsteam_gen.c" ]; then
    echo "error: generated sources missing. Build the Brovan project first (it runs the code generator)." >&2
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/obj/generated/exports.def" ]; then
    echo "error: generated exports.def missing." >&2
    exit 1
fi

mkdir -p "$SCRIPT_DIR/bin"

"$CC" -O2 -shared \
    -o "$SCRIPT_DIR/bin/steamclient64.dll" \
    "$SCRIPT_DIR/steamclient_shim.c" "$SCRIPT_DIR/obj/generated/exports.def" \
    -I "$SCRIPT_DIR" \
    -static -static-libgcc \
    -Wl,--out-implib,"$SCRIPT_DIR/bin/libsteamclient64.a" \
    -lkernel32

echo "Deploying steamclient64.dll:"

find "$REPO/Brovan/bin" -type f -name Brovan -o -type f -name Brovan.exe 2>/dev/null | while read -r exe; do
    vfs="$(dirname "$exe")/VirtualFS/C/Program Files (x86)/Steam"
    mkdir -p "$vfs"
    cp -f "$SCRIPT_DIR/bin/steamclient64.dll" "$vfs/steamclient64.dll"
    echo "  deployed -> $vfs/steamclient64.dll"
done
