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

#include "lazy_android_runtime.h"

#include <dlfcn.h>

#include <android-base/logging.h>

void LazyAndroidRuntime::load() {
    std::call_once(mLoadFlag, []() {
        void* handle = dlopen("libandroid_runtime.so", RTLD_LAZY);
        if (handle == nullptr) {
            LOG(WARNING) << "Could not open libandroid_runtime.";
            return;
        }

        ibinderForJavaObject = reinterpret_cast<BinderFromJava>(
                dlsym(handle, "_ZN7android20ibinderForJavaObjectEP7_JNIEnvP8_jobject"));
        if (ibinderForJavaObject == nullptr) {
            LOG(WARNING) << "Could not find ibinderForJavaObject.";
            // no return
        }

        javaObjectForIBinder = reinterpret_cast<BinderToJava>(dlsym(
                handle, "_ZN7android20javaObjectForIBinderEP7_JNIEnvRKNS_2spINS_7IBinderEEE"));
        if (javaObjectForIBinder == nullptr) {
            LOG(WARNING) << "Could not find javaObjectForIBinder.";
            // no return
        }

        parcelForJavaObject = reinterpret_cast<ParcelFromJava>(
                dlsym(handle, "_ZN7android19parcelForJavaObjectEP7_JNIEnvP8_jobject"));
        if (parcelForJavaObject == nullptr) {
            LOG(WARNING) << "Could not find parcelForJavaObject";
            // no return
        }
    });
}

LazyAndroidRuntime::BinderFromJava LazyAndroidRuntime::ibinderForJavaObject = nullptr;
LazyAndroidRuntime::BinderToJava LazyAndroidRuntime::javaObjectForIBinder = nullptr;
LazyAndroidRuntime::ParcelFromJava LazyAndroidRuntime::parcelForJavaObject = nullptr;
std::once_flag LazyAndroidRuntime::mLoadFlag;
