#!/usr/bin/env sh
set -e
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="$(cd "$HERE/../.." && pwd)"

[ -d "$HERE/bin" ] || { echo "no $HERE/bin; build it with build.ps1 on Windows or take it from the CI artifact" >&2; exit 1; }

find "$REPO/Brovan/bin" -type f -name Brovan 2>/dev/null | while IFS= read -r exe; do
    windows="$(dirname "$exe")/VirtualFS/C/Windows"
    mkdir -p "$windows"
    cp -Rf "$HERE/bin/." "$windows/"
    echo "deployed -> $windows"
done
