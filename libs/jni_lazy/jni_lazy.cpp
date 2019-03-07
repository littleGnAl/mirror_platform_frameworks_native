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

#include "jni_lazy.h"

#include <dlfcn.h> // dlopen, dlsym
#include <mutex> // once_flag, call_once

#include <android-base/logging.h> // LOG

namespace android {
namespace lazy {
namespace {

typedef JNIEnv* (*getJNIEnv_t)();
typedef sp<IBinder> (*ibinderForJavaObject_t)(JNIEnv* env, jobject obj);
typedef jobject (*javaObjectForIBinder_t)(JNIEnv* env, const sp<IBinder>& val);

std::once_flag gLoadFlag;

getJNIEnv_t getJNIEnv_;
ibinderForJavaObject_t ibinderForJavaObject_;
javaObjectForIBinder_t javaObjectForIBinder_;

void load() {
    std::call_once(gLoadFlag, []() {
        void* handle = dlopen("libandroid_runtime.so", RTLD_LAZY);
        if (handle == nullptr) {
            LOG(WARNING) << "Could not open libandroid_runtime.";
            return;
        }

        getJNIEnv_ = reinterpret_cast<getJNIEnv_t>(
                dlsym(handle, "_ZN7android14AndroidRuntime9getJNIEnvEv"));
        if (getJNIEnv_ == nullptr) {
            LOG(WARNING) << "Could not find getJNIEnv.";
            // no return
        }

        ibinderForJavaObject_ = reinterpret_cast<ibinderForJavaObject_t>(
                dlsym(handle, "_ZN7android20ibinderForJavaObjectEP7_JNIEnvP8_jobject"));
        if (ibinderForJavaObject_ == nullptr) {
            LOG(WARNING) << "Could not find ibinderForJavaObject.";
            // no return
        }

        javaObjectForIBinder_ = reinterpret_cast<javaObjectForIBinder_t>(
                 dlsym(handle, "_ZN7android20javaObjectForIBinderEP7_JNIEnvRKNS_2spINS_7IBinderEEE"));
        if (javaObjectForIBinder_ == nullptr) {
            LOG(WARNING) << "Could not find javaObjectForIBinder.";
            // no return
        }

    });
}

} // namespace

// exports delegate functions

JNIEnv* getJNIEnv() {
    load();
    if (getJNIEnv_ == nullptr) {
        return nullptr;
    }
    return (getJNIEnv_)();
}

sp<IBinder> ibinderForJavaObject(JNIEnv* env, jobject obj) {
    load();
    if (ibinderForJavaObject_ == nullptr) {
        return nullptr;
    }
    return (ibinderForJavaObject_)(env, obj);
}

jobject javaObjectForIBinder(JNIEnv* env, const sp<IBinder>& val) {
    load();
    if (javaObjectForIBinder_ == nullptr) {
        return nullptr;
    }
    return (javaObjectForIBinder_)(env, val);
}

} // namespace lazy
} // namespace android

