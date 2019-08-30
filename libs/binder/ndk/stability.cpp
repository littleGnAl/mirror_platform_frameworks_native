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

#include <android/binder_stability.h>

#include <android-base/logging.h>
#include <binder/Stability.h>
#include "ibinder_internal.h"

#include <dlfcn.h>

using ::android::internal::Stability;

#ifdef __ANDROID_VNDK__
#error libbinder_ndk should only be built in a system context
#endif

#ifdef __ANDROID_NDK__
#error libbinder_ndk should only be built in a system context
#endif

void AIBinder_markCompilationUnitStability(AIBinder* binder) {
    Dl_info info;
    if (0 == dladdr(__builtin_return_address(0), &info)) {
        LOG(FATAL) << "asdfasdf :( ???";
    }

    LOG(ERROR) << "asdfasdf path is " << info.dli_fname ? info.dli_fname : "NULL";

    // FIXME: mark correct group based on dli_fname
}

void AIBinder_markVintfStability(AIBinder* binder) {
    Stability::markVintf(binder->getBinder().get());
}
