#!/bin/sh

set -eu

if [ ! -f $ANDROID_BUILD_TOP/external/boringssl/CMakeLists.txt ]; then
    cd "$ANDROID_BUILD_TOP/external/boringssl"
    python3 src/util/generate_build_files.py cmake
fi

cd "$ANDROID_BUILD_TOP/frameworks/native/libs/binder/linux"

#CC=gcc CXX=g++ cmake \
CC=clang CXX=clang++ cmake \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DANDROID_BUILD_TOP=$ANDROID_BUILD_TOP \
    -DAIDL_BIN=$ANDROID_HOST_OUT/bin/aidl \
    -B build

cmake --build build
