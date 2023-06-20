#!/bin/sh

# Install dependencies:
# sudo apt install cmake ninja-build libgtest-dev

PREBUILT_HOST_OUT=`pwd`/../../../../../prebuilts/host/linux-x86
if [ -f "$PREBUILT_HOST_OUT/bin/aidl" ]; then
    export PATH="$PREBUILT_HOST_OUT/bin:$PATH"
    if [ -z $ANDROID_BUILD_TOP ]; then
        ANDROID_BUILD_TOP=`pwd`/../../../../..
    fi
    if [ -z $ANDROID_HOST_OUT ]; then
        ANDROID_HOST_OUT=$PREBUILT_HOST_OUT
    fi
fi

set -eu

if [ ! -f $ANDROID_HOST_OUT/bin/aidl ]; then
    echo "Please run:"
    echo "m -j aidl"
    exit
fi

cd "$ANDROID_BUILD_TOP/frameworks/native/libs/binder/linux"

CC=clang CXX=clang++ cmake \
    -G Ninja \
    -DCMAKE_BUILD_TYPE=Release \
    -DANDROID_BUILD_TOP=$ANDROID_BUILD_TOP \
    -DAIDL_BIN=$ANDROID_HOST_OUT/bin/aidl \
    -B build

cmake --build build
