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

#pragma once

#include <binder/IBinder.h>
#include <string>

namespace android {

// WARNING: These APIs are only ever expected to be called by auto-generated code.
//     Instead of calling them, you should set the stability of a .aidl interface
class Stability final {
public:
    // This must be called as soon as the binder in question is constructed. No thread safety
    // is provided.
    // E.g. stability is according to libbinder compilation unit
    static void markCompilationUnit(const sp<IBinder>& binder);
    // WARNING: This is only ever expected to be called by auto-generated code. You likely want to
    // change or modify the stability class of the interface you are using.
    // This must be called as soon as the binder in question is constructed. No thread safety
    // is provided.
    // E.g. stability is according to libbinder_ndk or Java SDK AND the interface
    //     expressed here is guaranteed to be stable for multiple years (Stable AIDL)
    static void markVintf(const sp<IBinder>& binder);

private:
    Stability();
};

}  // namespace android
