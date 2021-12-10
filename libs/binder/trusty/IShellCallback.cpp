/*
 * Copyright (C) 2016 The Android Open Source Project
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

#define LOG_TAG "ShellCallback"

#include <fcntl.h>
#include <unistd.h>

#include <binder/IShellCallback.h>

#include <binder/Parcel.h>
#include <utils/Log.h>
#include <utils/String8.h>

namespace android {

// ----------------------------------------------------------------------

class BpShellCallback : public BpInterface<IShellCallback> {
public:
    explicit BpShellCallback(const sp<IBinder>& impl) : BpInterface<IShellCallback>(impl) {}

    virtual int openFile(const String16&, const String16&, const String16&) {
        return INVALID_OPERATION;
    }
};

IMPLEMENT_META_INTERFACE(ShellCallback, "com.android.internal.os.IShellCallback")

} // namespace android
