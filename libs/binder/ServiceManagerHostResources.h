/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <android-base/macros.h>
#include <android/os/IServiceManager.h>

#include "Utils.h"

namespace android {

// RAII object for adb forwarding
class AdbForwarder {
public:
    AdbForwarder() = default;
    static std::optional<AdbForwarder> forward(unsigned int devicePort);
    AdbForwarder(AdbForwarder&& other) noexcept { (*this) = std::move(other); }
    AdbForwarder& operator=(AdbForwarder&&) noexcept;
    ~AdbForwarder();
    [[nodiscard]] const std::optional<unsigned int>& hostPort() const { return mPort; }

private:
    DISALLOW_COPY_AND_ASSIGN(AdbForwarder);
    explicit AdbForwarder(unsigned int port) : mPort(port) {}
    std::optional<unsigned int> mPort;
};

class ServiceManagerHostResources {
public:
    static ServiceManagerHostResources create();
    const sp<android::os::IServiceManager>& impl() const { return mImpl; }

private:
    sp<android::os::IServiceManager> mImpl;
    CommandResult mCommandResult;
    AdbForwarder mAdbForwarder;
};

} // namespace android
