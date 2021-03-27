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

#include "MemtrackProxy.h"

#include <android-base/logging.h>
#include <android/binder_manager.h>
#include <android/hardware/memtrack/translate-ndk.h>
#include <private/android_filesystem_config.h>

using ::aidl::android::hardware::memtrack::h2a::translate;
using ::android::hardware::hidl_vec;
using ::android::hardware::Return;

namespace aidl {
namespace android {
namespace hardware {
namespace memtrack {

sp<V1_0_hidl::IMemtrack> MemtrackProxy::MemtrackHidlInstance() {
    return V1_0_hidl::IMemtrack::getService();
}

std::shared_ptr<V_aidl::IMemtrack> MemtrackProxy::MemtrackAidlInstance() {
    const auto instance = std::string() + V_aidl::IMemtrack::descriptor + "/default";
    bool declared = AServiceManager_isDeclared(instance.c_str());
    if (!declared) {
        return nullptr;
    }
    ndk::SpAIBinder memtrack_binder =
            ndk::SpAIBinder(AServiceManager_waitForService(instance.c_str()));
    return V_aidl::IMemtrack::fromBinder(memtrack_binder);
}

bool MemtrackProxy::CheckUid(uid_t calling_uid) {
    return calling_uid == AID_SYSTEM || calling_uid == AID_ROOT;
}

bool MemtrackProxy::CheckPid(pid_t calling_pid, pid_t request_pid) {
    return calling_pid == request_pid;
}

MemtrackProxy::MemtrackProxy()
      : memtrack_hidl_instance_(MemtrackProxy::MemtrackHidlInstance()),
        memtrack_aidl_instance_(MemtrackProxy::MemtrackAidlInstance()) {}

ndk::ScopedAStatus MemtrackProxy::getMemory(int pid, MemtrackType type,
                                            std::vector<MemtrackRecord>* _aidl_return) {
    if (pid < 0) {
        return ndk::ScopedAStatus::fromExceptionCode(EX_ILLEGAL_ARGUMENT);
    }

    const char* err_msg = "Only AID_ROOT and AID_SYSTEM can request getMemory() for PIDs other "
                          "than the calling PID";
    if (!MemtrackProxy::CheckPid(AIBinder_getCallingPid(), pid) &&
        !MemtrackProxy::CheckUid(AIBinder_getCallingUid())) {
        return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_SECURITY, err_msg);
    }

    if (type != MemtrackType::OTHER && type != MemtrackType::GL && type != MemtrackType::GRAPHICS &&
        type != MemtrackType::MULTIMEDIA && type != MemtrackType::CAMERA) {
        return ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
    }

    _aidl_return->clear();

    if (memtrack_aidl_instance_ ||
        (memtrack_aidl_instance_ = MemtrackProxy::MemtrackAidlInstance())) {
        return memtrack_aidl_instance_->getMemory(pid, type, _aidl_return);
    } else if (memtrack_hidl_instance_ ||
               (memtrack_hidl_instance_ = MemtrackProxy::MemtrackHidlInstance())) {
        ndk::ScopedAStatus aidl_status;

        Return<void> ret = memtrack_hidl_instance_->getMemory(
                pid, static_cast<V1_0_hidl::MemtrackType>(type),
                [&_aidl_return, &aidl_status](V1_0_hidl::MemtrackStatus status,
                                              hidl_vec<V1_0_hidl::MemtrackRecord> records) {
                    switch (status) {
                        case V1_0_hidl::MemtrackStatus::SUCCESS:
                            aidl_status = ndk::ScopedAStatus::ok();
                            break;
                        case V1_0_hidl::MemtrackStatus::MEMORY_TRACKING_NOT_SUPPORTED:
                            [[fallthrough]];
                        case V1_0_hidl::MemtrackStatus::TYPE_NOT_SUPPORTED:
                            [[fallthrough]];
                        default:
                            aidl_status =
                                    ndk::ScopedAStatus::fromExceptionCode(EX_UNSUPPORTED_OPERATION);
                            return;
                    }

                    _aidl_return->resize(records.size());
                    for (size_t i = 0; i < records.size(); i++) {
                        if (!translate(records[i], &(*_aidl_return)[i])) {
                            const char* err_msg = "Failed to convert HIDL MemtrackRecord to AIDL";
                            aidl_status = ndk::ScopedAStatus::
                                    fromExceptionCodeWithMessage(EX_SERVICE_SPECIFIC, err_msg);
                            return;
                        }
                    }
                });

        // Check HIDL return
        if (!ret.isOk()) {
            const char* err_msg = "HIDL Memtrack::getMemory() failed";
            aidl_status =
                    ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_SERVICE_SPECIFIC, err_msg);
            LOG(ERROR) << err_msg << ": " << ret.description();
        }

        return aidl_status;
    }

    return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_NULL_POINTER,
                                                            "Memtrack HAL service not available");
}

ndk::ScopedAStatus MemtrackProxy::getGpuDeviceInfo(std::vector<DeviceInfo>* _aidl_return) {
    if (!MemtrackProxy::CheckUid(AIBinder_getCallingUid())) {
        const char* err_msg = "Only AID_ROOT and AID_SYSTEM can request getGpuDeviceInfo()";
        return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_SECURITY, err_msg);
    }

    _aidl_return->clear();

    if (memtrack_aidl_instance_ ||
        (memtrack_aidl_instance_ = MemtrackProxy::MemtrackAidlInstance())) {
        return memtrack_aidl_instance_->getGpuDeviceInfo(_aidl_return);
    }

    return ndk::ScopedAStatus::fromExceptionCodeWithMessage(EX_NULL_POINTER,
                                                            "Memtrack HAL service not available");
}

} // namespace memtrack
} // namespace hardware
} // namespace android
} // namespace aidl
