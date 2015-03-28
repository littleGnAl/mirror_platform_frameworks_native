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
 * @file bitmap.h
 */

#ifndef ANDROID_BITMAP_H
#define ANDROID_BITMAP_H

#include <stdint.h>
#include <jni.h>

#ifdef __cplusplus
extern "C" {
#endif

/** success */
#define ANDROID_BITMAP_RESULT_SUCCESS            0
/** bad parameter */
#define ANDROID_BITMAP_RESULT_BAD_PARAMETER     -1
/** jni exception */
#define ANDROID_BITMAP_RESULT_JNI_EXCEPTION     -2
/** allocation failed */
#define ANDROID_BITMAP_RESULT_ALLOCATION_FAILED -3

/** Backward compatibility: this macro used to be misspelled. */
#define ANDROID_BITMAP_RESUT_SUCCESS ANDROID_BITMAP_RESULT_SUCCESS

/** Bitmap pixel format */
enum AndroidBitmapFormat {
    ANDROID_BITMAP_FORMAT_NONE      = 0,
    /** red: 8 bits, green: 8 bits, blue: 8 bits, alpha: 8 bits **/
    ANDROID_BITMAP_FORMAT_RGBA_8888 = 1,
    /** red: 5 bits, green: 6 bits, blue: 5 bits **/
    ANDROID_BITMAP_FORMAT_RGB_565   = 4,
    /** red: 4 bits, green: 4 bits, blue: 4 bits, alpha: 4 bits **/
    ANDROID_BITMAP_FORMAT_RGBA_4444 = 7,
    /** Deprecated */
    ANDROID_BITMAP_FORMAT_A_8       = 8,
};

/** Bitmap info, see AndroidBitmap_getInfo() */
typedef struct {
    /** bitmap width in pixels */
    uint32_t    width;
    /** bitmap height in pixels */
    uint32_t    height;
    /** number of byte per row */
    uint32_t    stride;
    /** see {@link AndroidBitmapFormat} */
    int32_t     format;
    /** unused */
    uint32_t    flags;      // 0 for now
} AndroidBitmapInfo;

/**
 * Given a java bitmap object, fill out the AndroidBitmapInfo struct for it.
 * If the call fails, the info parameter will be ignored
 */
int AndroidBitmap_getInfo(JNIEnv* env, jobject jbitmap,
                          AndroidBitmapInfo* info);

/**
 * Given a java bitmap object, attempt to lock the pixel address.
 * Locking will ensure that the memory for the pixels will not move
 * until the unlockPixels call, and ensure that, if the pixels had been
 * previously purged, they will have been restored.
 *
 * If this call succeeds, it must be balanced by a call to
 * AndroidBitmap_unlockPixels, after which time the address of the pixels should
 * no longer be used.
 *
 * If this succeeds, *addrPtr will be set to the pixel address. If the call
 * fails, addrPtr will be ignored.
 */
int AndroidBitmap_lockPixels(JNIEnv* env, jobject jbitmap, void** addrPtr);

/**
 * Call this to balance a successful call to AndroidBitmap_lockPixels
 */
int AndroidBitmap_unlockPixels(JNIEnv* env, jobject jbitmap);

#ifdef __cplusplus
}
#endif

#endif
