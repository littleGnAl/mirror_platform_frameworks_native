#!/bin/sh

set -eu

cd "$ANDROID_BUILD_TOP/frameworks/native/libs/binder/linux"

CC=clang CXX=clang++ cmake \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DANDROID_BUILD_TOP=$ANDROID_BUILD_TOP \
    -DAIDL_BIN=$ANDROID_HOST_OUT/bin/aidl \
    -DBORINGSSL_SKIP_TESTS=1 \
    -B build

cmake --build build
