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

if [ ! -f "$SCRIPT_DIR/obj/generated/brovvulk_gen.c" ]; then
    echo "error: generated sources missing. Build the Brovan project first (it runs the code generator)." >&2
    exit 1
fi

if [ ! -f "$SCRIPT_DIR/obj/generated/exports.def" ]; then
    echo "error: generated exports.def missing." >&2
    exit 1
fi

mkdir -p "$SCRIPT_DIR/bin"

"$CC" -O2 -shared \
    -o "$SCRIPT_DIR/bin/vulkan-1.dll" \
    "$SCRIPT_DIR/vulkan_shim.c" "$SCRIPT_DIR/obj/generated/exports.def" \
    -I "$SCRIPT_DIR" -I "$SCRIPT_DIR/../vulkan-headers" \
    -static -static-libgcc -static-libstdc++ \
    -Wl,--out-implib,"$SCRIPT_DIR/bin/libvulkan-1.a" \
    -lkernel32

CC32="${CC32:-i686-w64-mingw32-gcc}"
BUILT_X86=0
if command -v "$CC32" >/dev/null 2>&1; then
    mkdir -p "$SCRIPT_DIR/bin/x86"
    "$CC32" -O2 -shared \
        -o "$SCRIPT_DIR/bin/x86/vulkan-1.dll" \
        "$SCRIPT_DIR/vulkan_shim.c" "$SCRIPT_DIR/obj/generated/exports.def" \
        -I "$SCRIPT_DIR" -I "$SCRIPT_DIR/../vulkan-headers" \
        -static -static-libgcc -static-libstdc++ \
        -Wl,--out-implib,"$SCRIPT_DIR/bin/x86/libvulkan-1.a" \
        -lkernel32
    BUILT_X86=1
else
    echo "warning: '$CC32' not found; skipping the 32-bit SysWOW64 shim (set CC32 to build it)." >&2
fi

deploy_one() {
    dst="$1/C/Windows/System32"
    mkdir -p "$dst"
    cp -f "$SCRIPT_DIR/bin/vulkan-1.dll" "$dst/vulkan-1.dll"
    echo "  deployed -> $dst/vulkan-1.dll"

    if [ "$BUILT_X86" -eq 1 ]; then
        dst32="$1/C/Windows/SysWOW64"
        mkdir -p "$dst32"
        cp -f "$SCRIPT_DIR/bin/x86/vulkan-1.dll" "$dst32/vulkan-1.dll"
        echo "  deployed -> $dst32/vulkan-1.dll"
    fi
}

echo "Deploying vulkan-1.dll:"
deploy_one "$REPO/VirtualFS"

if [ -d "$REPO/Brovan/bin" ]; then
    find "$REPO/Brovan/bin" -type f -name Brovan.exe 2>/dev/null | while IFS= read -r exe; do
        deploy_one "$(dirname "$exe")/VirtualFS"
    done
fi

if [ -d "$REPO/Brovan.Graphics" ]; then
    find "$REPO/Brovan.Graphics" -type f -name Brovan.exe 2>/dev/null | while IFS= read -r exe; do
        deploy_one "$(dirname "$exe")/VirtualFS"
    done
fi