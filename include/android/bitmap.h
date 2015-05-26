/*
 * Copyright (C) 2009 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * @addtogroup Bitmap
 * @{
 */

/**
 * @file bitmap.h
 */

#ifndef ANDROID_BITMAP_H
#define ANDROID_BITMAP_H

#include <stdint.h>
#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Result codes for <code> AndroidBitmap*</code> functions. */
enum {
    /** Operation completed successfully. */
    ANDROID_BITMAP_RESULT_SUCCESS           = 0,
    /** A bad parameter was passed. */
    ANDROID_BITMAP_RESULT_BAD_PARAMETER     = -1,
    /** JNI exception occured. */
    ANDROID_BITMAP_RESULT_JNI_EXCEPTION     = -2,
    /** Allocation failed. */
    ANDROID_BITMAP_RESULT_ALLOCATION_FAILED = -3,
};

/** For backward compatibility with a macro that used to be misspelled. */
#define ANDROID_BITMAP_RESUT_SUCCESS ANDROID_BITMAP_RESULT_SUCCESS

/** Bitmap pixel format. */
enum AndroidBitmapFormat {
    /** No format. */
    ANDROID_BITMAP_FORMAT_NONE      = 0,
    /** Red: 8 bits, Green: 8 bits, Blue: 8 bits, Alpha: 8 bits. **/
    ANDROID_BITMAP_FORMAT_RGBA_8888 = 1,
    /** Red: 5 bits, Green: 6 bits, Blue: 5 bits. **/
    ANDROID_BITMAP_FORMAT_RGB_565   = 4,
    /** Red: 4 bits, Green: 4 bits, Blue: 4 bits, Alpha: 4 bits. **/
    ANDROID_BITMAP_FORMAT_RGBA_4444 = 7,
    /** Deprecated. */
    ANDROID_BITMAP_FORMAT_A_8       = 8,
};

/** Bitmap info. For more information, see {@link AndroidBitmap_getInfo()}. */
typedef struct {
    /** The bitmap width in pixels. */
    uint32_t    width;
    /** The bitmap height in pixels. */
    uint32_t    height;
    /** The number of bytes per row. */
    uint32_t    stride;
    /** The bitmap pixel format. For more information, see {@link AndroidBitmapFormat} */
    int32_t     format;
    /** Unused. */
    uint32_t    flags;      // 0 for now
} AndroidBitmapInfo;

/**
 * Given a Java <code>bitmap</code> object, fill out the AndroidBitmapInfo struct for it.
 * If the call fails, the info parameter is ignored.
 */
int AndroidBitmap_getInfo(JNIEnv* env, jobject jbitmap,
                          AndroidBitmapInfo* info);

/**
 * Given a Java <code>bitmap</code> object, attempt to lock the pixel address.
 * Locking ensures that the memory for the pixels does not move
 * until the {@link AndroidBitmap_unlockPixels()} call, and ensure that previously
 * purged pixels are restored.
 *
 * If this call succeeds, it must be balanced by a call to
 * AndroidBitmap_unlockPixels(), after which the address of the pixels should
 * no longer be used. (TODO: @proppy: The following sentence is also if _lockPixels
 * succeeds, right?) Further, <code>*addrPtr</code> is set to the pixel address.
 * If the call fails, <code>addrPtr</code> is ignored.
 */
int AndroidBitmap_lockPixels(JNIEnv* env, jobject jbitmap, void** addrPtr);

/**
 * Unlocks pixels that AndroidBitmap_lockPixels() had successfully locked. Required
 * in order to balance out AndroidBitmap_lockPixels()
 */
int AndroidBitmap_unlockPixels(JNIEnv* env, jobject jbitmap);

#ifdef __cplusplus
}
#endif

#endif

/** @} */
