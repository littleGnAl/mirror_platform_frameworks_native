/*
 * Copyright (C) 2019 The Android Open Source Project
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
 * @addtogroup NdkBinder
 * @{
 */

/**
 * @file binder_parcel_jni.h
 * @brief Conversions between Parcel and android.os.Parcel
 */

#pragma once

#include <android/binder_parcel.h>

#include <jni.h>

__BEGIN_DECLS
#if __ANDROID_API__ >= __ANDROID_API_Q__

/**
 * Converts an android.os.Parcel object into an AParcel* object.
 *
 * If either env or the parcel is null, null is returned. If the object is non-null, it must be
 * deleted with AParcel_delete.
 *
 * \param env Java environment.
 * \param parcel android.os.Parcel java object.
 *
 * \return an AParcel object representing the Java parcel object. If either parameter is null this
 * will fail.
 */
__attribute__((warn_unused_result)) AParcel* AParcel_fromJavaParcel(JNIEnv* env, jobject parcel)
        __INTRODUCED_IN(29);

#endif  //__ANDROID_API__ >= __ANDROID_API_Q__
__END_DECLS

/** @} */
