#!/usr/bin/env bash

set -e

echo "Formatting code"

bpfmt -w $ANDROID_BUILD_TOP/frameworks/native/libs/binder/ndk/Android.bp
clang-format -i $(find $ANDROID_BUILD_TOP/frameworks/native/libs/binder/ndk/ -\( -name "*.cpp" -o -name "*.h" -\))
