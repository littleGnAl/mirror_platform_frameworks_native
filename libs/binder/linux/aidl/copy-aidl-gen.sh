#!/bin/sh

set -eu

OUTDIR=$1

if [ ! -f $OUTDIR/aidl_language_y.cpp ]; then
    cp $ANDROID_BUILD_TOP/out/soong/.intermediates/system/tools/aidl/libaidl-common/linux_glibc_x86_64_static/gen/yacc/system/tools/aidl/* $OUTDIR/
fi

if [ ! -f $OUTDIR/aidl_language_l.cpp ]; then
    lex --outfile=$OUTDIR/aidl_language_l.cpp $ANDROID_BUILD_TOP/system/tools/aidl/aidl_language_l.ll
fi
