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

// TODO(b/118783779): replace with trampoline library or refactor pieces out of libandroid_runtime
// based on PDK build direction

#pragma once

#include <jni.h>

#include <binder/IBinder.h>
#include <binder/Parcel.h>

#include <mutex>

struct LazyAndroidRuntime {
    typedef ::android::sp<::android::IBinder> (*BinderFromJava)(JNIEnv* env, jobject obj);
    typedef jobject (*BinderToJava)(JNIEnv* env, const ::android::sp<::android::IBinder>& val);

    typedef ::android::Parcel* (*ParcelFromJava)(JNIEnv* env, jobject obj);

    static BinderFromJava ibinderForJavaObject;
    static BinderToJava javaObjectForIBinder;

    static ParcelFromJava parcelForJavaObject;

    static void load();

   private:
    static std::once_flag mLoadFlag;

    LazyAndroidRuntime(){};
};
