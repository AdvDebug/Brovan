#!/usr/bin/env bash
# Rebuilds the BCn modules from bcdecode.comp, one per output format. ETC2 transcodes rather than
# decodes: it writes encoded blocks to a buffer for a copy, the rest write texels to a storage image.
# The .spv files are checked in and embedded into Brovan.dll, so this only runs when the shader changes.
set -e
cd "$(dirname "$0")"

GLSLC=${GLSLC:-glslc}
SPIRV_VAL=${SPIRV_VAL:-spirv-val}

for Variant in RGBA8 RG8 R8 RGBA16 ETC2; do
    Name=$(echo "$Variant" | tr '[:upper:]' '[:lower:]')
    "$GLSLC" --target-env=vulkan1.1 -O -DBC_OUT_$Variant -o "bcdecode_$Name.spv" bcdecode.comp
    "$SPIRV_VAL" --target-env vulkan1.1 "bcdecode_$Name.spv"
    echo "built bcdecode_$Name.spv"
done
