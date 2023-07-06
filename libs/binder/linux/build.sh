#!/bin/sh

# Install dependencies:
# sudo apt install cmake ninja-build libgtest-dev
# sudo apt install flex

if [ -z $ANDROID_BUILD_TOP ]; then
    export ANDROID_BUILD_TOP=`pwd`/../../../../..
fi

set -eu

cd "$ANDROID_BUILD_TOP/frameworks/native/libs/binder/linux"

mkdir -p aidl/gen
aidl/copy-aidl-gen.sh aidl/gen

# Release build doesn't pass tests on RPi due to some race condition, let's stick to Debug for now
CC=clang CXX=clang++ cmake \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DANDROID_BUILD_TOP=$ANDROID_BUILD_TOP \
    -B build

cmake --build build
