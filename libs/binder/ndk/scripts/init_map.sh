#!/usr/bin/env bash

# Simple helper for ease of development until this API is frozen.

echo "LIBBINDER_NDK {"
echo "  global:"
{
    grep -oP "AParcel_[a-zA-Z0-9_]+(?=\()" include_ndk/android/binder_parcel.h | awk '{ print "    "$0";"; }';
    grep -oP "AIBinder_[a-zA-Z0-9_]+(?=\()" include_ndk/android/binder_ibinder.h | awk '{ print "    "$0";"; }';
    grep -oP "AWeak_[a-zA-Z0-9_]+(?=\()" include_ndk/android/binder_ibinder.h | awk '{ print "    "$0";"; }';
} | sort | uniq
echo "  local:"
echo "    *;"
echo "};"
