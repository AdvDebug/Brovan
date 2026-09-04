#!/usr/bin/env bash
# Rebuilds the BCn decoder modules from bcdecode.comp, one per output format. The .spv files are checked in
# and embedded into Brovan.dll, so this only has to run when the shader changes.
set -e
cd "$(dirname "$0")"

GLSLC=${GLSLC:-glslc}
SPIRV_VAL=${SPIRV_VAL:-spirv-val}

for Variant in RGBA8 RG8 R8 RGBA16; do
    Name=$(echo "$Variant" | tr '[:upper:]' '[:lower:]')
    "$GLSLC" --target-env=vulkan1.1 -O -DBC_OUT_$Variant -o "bcdecode_$Name.spv" bcdecode.comp
    "$SPIRV_VAL" --target-env vulkan1.1 "bcdecode_$Name.spv"
    echo "built bcdecode_$Name.spv"
done
