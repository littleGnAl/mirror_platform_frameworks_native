#!/bin/sh

# Install dependencies:
# sudo apt install cmake ninja-build libgtest-dev
# sudo apt install flex

# Build prerequisites:
# m aidl

if [ -z $ANDROID_BUILD_TOP ]; then
    export ANDROID_BUILD_TOP=`pwd`/../../../../..
fi
if [ -z $CC ]; then
    echo "CC not set, setting default"
    export CC=gcc
fi
if [ -z $CXX ]; then
    echo "CXX not set, setting default"
    export CXX=g++
fi

set -eu

cd "$ANDROID_BUILD_TOP/frameworks/native/libs/binder/linux"

mkdir -p aidl/gen
aidl/copy-aidl-gen.sh aidl/gen

# Release build doesn't pass tests on RPi due to some race condition, let's stick to Debug for now
cmake \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Debug \
    -DANDROID_BUILD_TOP=$ANDROID_BUILD_TOP \
    -B build

cmake --build build
