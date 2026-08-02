#!/usr/bin/env bash
# Builds the Brovan APK. Must run on a Linux host (WSL is fine): NativeAOT does not cross-compile from
# Windows to linux-bionic.
#
# Expects a .NET 9 SDK (the source generator needs Roslyn >= 4.10), a JDK 17, Gradle 8.7+, and an Android
# SDK with NDK 26. Point the variables below at them if they are not already on PATH.
set -euo pipefail

ANDROID_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$ANDROID_DIR/../.." && pwd)"
PROJECT="$REPO_ROOT/Brovan/Brovan.csproj"
GRADLE_PROJECT="$ANDROID_DIR/app"
JNI_LIBS="$GRADLE_PROJECT/brovan/src/main/jniLibs/arm64-v8a"

TOOLS="${BROVAN_TOOLCHAIN:-$HOME/brovan-toolchain}"

DOTNET="${DOTNET:-}"
if [ -z "$DOTNET" ]; then
    if [ -x "$HOME/.dotnet9/dotnet" ]; then
        DOTNET="$HOME/.dotnet9/dotnet"
    else
        DOTNET="$(command -v dotnet || true)"
    fi
fi

if [ -z "${JAVA_HOME:-}" ] || [ ! -d "${JAVA_HOME:-}" ]; then
    if [ -d "$TOOLS/jdk17" ]; then
        export JAVA_HOME="$TOOLS/jdk17"
    else
        unset JAVA_HOME
    fi
fi

export ANDROID_SDK_ROOT="${ANDROID_SDK_ROOT:-$TOOLS/android-sdk}"
export ANDROID_HOME="$ANDROID_SDK_ROOT"

GRADLE="${GRADLE:-}"
if [ -z "$GRADLE" ]; then
    if [ -x "$TOOLS/gradle-8.7/bin/gradle" ]; then
        GRADLE="$TOOLS/gradle-8.7/bin/gradle"
    else
        GRADLE="$(command -v gradle || true)"
    fi
fi

# The trailing `|| true` keeps pipefail from ending the script here when the SDK is not installed at all:
# these have to report "no toolchain" through missing() below, not abort.
NDK="${ANDROID_NDK_HOME:-}"
[ -n "$NDK" ] || NDK="$(ls -d "$ANDROID_SDK_ROOT"/ndk/* 2>/dev/null | sort -V | tail -1 || true)"
CMAKE="${CMAKE:-}"
[ -n "$CMAKE" ] || CMAKE="$(ls -d "$ANDROID_SDK_ROOT"/cmake/*/bin/cmake 2>/dev/null | sort -V | tail -1 || true)"
[ -x "${CMAKE:-}" ] || CMAKE="$(command -v cmake || true)"

CONFIG="${CONFIG:-Release}"
API_LEVEL="${API_LEVEL:-26}"
PUBLISH_DIR="${BROVAN_PUBLISH_DIR:-/tmp/brovan-android-publish}"
APK_OUTPUT="${BROVAN_APK_OUTPUT:-$REPO_ROOT/artifacts/android/brovan-arm64-v8a.apk}"
UNICORN_SRC="$REPO_ROOT/Brovan/.cache/unicorn/unicorn-2.1.4"
UNICORN_BUILD="$REPO_ROOT/Brovan/.cache/unicorn/build-android-arm64"
UNICORN_ARTIFACT="$UNICORN_BUILD/libunicorn.so"

# Exit code 3 means "this host has no Android toolchain", which Brovan.Android/Brovan.Android.csproj treats
# as a skip rather than a build failure. Anything else is a real failure.
missing() { echo "$1" >&2; exit 3; }

[ -n "$DOTNET" ] && [ -x "$DOTNET" ] || missing "dotnet SDK not found; set DOTNET or install one at $HOME/.dotnet9"
DOTNET_MAJOR="$("$DOTNET" --version 2>/dev/null | cut -d. -f1)"
case "${DOTNET_MAJOR:-}" in
    ''|*[!0-9]*) missing "could not read the SDK version of $DOTNET" ;;
esac
[ "$DOTNET_MAJOR" -ge 9 ] || missing "the source generator needs Roslyn >= 4.10, so a .NET 9 SDK is required; $DOTNET is $DOTNET_MAJOR.x"
[ -n "$GRADLE" ] && [ -x "$GRADLE" ] || missing "gradle not found; set GRADLE (8.7 or newer, required by AGP 8.5)"
[ -n "$NDK" ] && [ -d "$NDK" ] || missing "Android NDK not found under $ANDROID_SDK_ROOT/ndk"
[ -n "${CMAKE:-}" ] && [ -x "$CMAKE" ] || missing "cmake not found"

mkdir -p "$JNI_LIBS"

if [ ! -f "$UNICORN_SRC/CMakeLists.txt" ]; then
    echo "==> Fetching the Unicorn source through Brovan.Unicorn.targets"
    "$DOTNET" msbuild "$PROJECT" -t:ExtractUnicornSource -nologo -v:minimal || true
    [ -f "$UNICORN_SRC/CMakeLists.txt" ] || { echo "Unicorn source missing at $UNICORN_SRC" >&2; exit 1; }
fi

# Unicorn has to be cross-built before the publish: Brovan.Unicorn.targets copies whatever sits at
# UnicornArtifact into the publish output, and if that path is empty it configures a host-arch build there
# instead, poisoning the CMake cache for the arm64 configure that follows.
echo "==> [1/4] Cross-building Unicorn for arm64-v8a"
if [ ! -f "$UNICORN_ARTIFACT" ]; then
    "$CMAKE" -S "$UNICORN_SRC" -B "$UNICORN_BUILD" \
        -DCMAKE_TOOLCHAIN_FILE="$NDK/build/cmake/android.toolchain.cmake" \
        -DANDROID_ABI=arm64-v8a \
        -DANDROID_PLATFORM="android-$API_LEVEL" \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_SHARED_LINKER_FLAGS="-Wl,-z,max-page-size=16384" \
        -DUNICORN_ARCH="x86;aarch64" \
        -DBUILD_SHARED_LIBS=ON \
        -DUNICORN_LEGACY_STATIC_ARCHIVE=OFF \
        -DUNICORN_FUZZ=OFF \
        -DUNICORN_LOGGING=OFF \
        -DUNICORN_BUILD_TESTS=OFF
    "$CMAKE" --build "$UNICORN_BUILD" --parallel
fi
cp "$UNICORN_ARTIFACT" "$JNI_LIBS/libunicorn.so"

# .NET's crypto shim aborts the process the moment any OpenSSL-backed primitive is touched
# ("No usable version of libssl was found"), and Android exposes no libssl to apps. Its probe list includes
# the unversioned names, which is what OpenSSL's android targets emit and what Android will package.
OPENSSL_BUILD="${OPENSSL_BUILD:-$TOOLS/openssl-3.5.4}"
if [ -f "$OPENSSL_BUILD/libssl.so" ] && [ -f "$OPENSSL_BUILD/libcrypto.so" ]; then
    cp "$OPENSSL_BUILD/libssl.so" "$OPENSSL_BUILD/libcrypto.so" "$JNI_LIBS/"
else
    echo "warning: no OpenSSL build at $OPENSSL_BUILD; the guest will abort on first crypto use" >&2
fi

echo "==> [2/4] Publishing Brovan as a NativeAOT shared library (linux-bionic-arm64)"
NDK_BIN="$NDK/toolchains/llvm/prebuilt/linux-x86_64/bin"
CLANG="$NDK_BIN/aarch64-linux-android$API_LEVEL-clang"
OBJCOPY="$NDK_BIN/llvm-objcopy"
[ -x "$CLANG" ] || missing "NDK clang not found at $CLANG"
[ -x "$OBJCOPY" ] || missing "NDK llvm-objcopy not found at $OBJCOPY"

rm -rf "$PUBLISH_DIR"
# PublishAot is set inside Brovan.csproj on purpose: passing it on the command line leaks it into the
# netstandard2.0 generator project, which fails with NETSDK1207.
"$DOTNET" publish "$PROJECT" \
    -c "$CONFIG" \
    -r linux-bionic-arm64 \
    --self-contained true \
    -p:NativeLib=Shared \
    -p:OutputType=Library \
    -p:PublishAotUsingRuntimePack=true \
    -p:PlatformTarget=arm64 \
    -p:CppCompilerAndLinker="$CLANG" \
    -p:ObjCopyName="$OBJCOPY" \
    -p:LinkerFlavor=lld \
    -p:CustomAfterMicrosoftCommonTargets="$ANDROID_DIR/android-link.targets" \
    -p:UnicornBuildDir="$UNICORN_BUILD" \
    -p:UnicornArtifact="$UNICORN_ARTIFACT" \
    -o "$PUBLISH_DIR"

# NativeAOT names the shared library after the assembly and drops the lib prefix on some SDKs.
PRODUCED="$(find "$PUBLISH_DIR" -maxdepth 1 -name 'Brovan.so' -o -maxdepth 1 -name 'libBrovan.so' | head -1)"
[ -n "$PRODUCED" ] || { echo "no shared library produced in $PUBLISH_DIR" >&2; ls -la "$PUBLISH_DIR" >&2; exit 1; }
cp "$PRODUCED" "$JNI_LIBS/libBrovan.so"
file "$JNI_LIBS/libBrovan.so"

echo "==> [3/4] Assembling the APK"
printf 'sdk.dir=%s\n' "$ANDROID_SDK_ROOT" > "$GRADLE_PROJECT/local.properties"
"$GRADLE" -p "$GRADLE_PROJECT" assembleDebug --no-daemon

echo "==> [4/4] Collecting the APK"
BUILT_APK="$(find "$GRADLE_PROJECT" -path '*/outputs/apk/debug/*.apk' -print | head -1)"
[ -n "$BUILT_APK" ] || { echo "gradle produced no APK under $GRADLE_PROJECT" >&2; exit 1; }
mkdir -p "$(dirname "$APK_OUTPUT")"
cp "$BUILT_APK" "$APK_OUTPUT"
echo "$APK_OUTPUT"
