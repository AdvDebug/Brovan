cmake_minimum_required(VERSION 3.22)
project(brovan_jni C)

add_library(brovan_jni SHARED brovan_jni.c)

# libBrovan.so is the NativeAOT shared library published from Brovan.csproj; BROVAN_LIB_DIR must point at
# the jniLibs directory it was copied into for the current ABI. find_library is deliberately not used: the
# NDK toolchain sets CMAKE_FIND_ROOT_PATH_MODE_LIBRARY to ONLY, so it searches the sysroot and ignores PATHS.
set(BROVAN_LIB "${BROVAN_LIB_DIR}/libBrovan.so")
if(NOT EXISTS "${BROVAN_LIB}")
    message(FATAL_ERROR "libBrovan.so not found at ${BROVAN_LIB}; publish Brovan for linux-bionic-arm64 first")
endif()

target_link_libraries(brovan_jni "${BROVAN_LIB}" android jnigraphics log)

# Android 16 warns about 4K-aligned libraries and 16K-page devices reject them outright.
target_link_options(brovan_jni PRIVATE "-Wl,-z,max-page-size=16384")
