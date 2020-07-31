/*
 * Copyright 2020 The Android Open Source Project
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

#define LOG_TAG "Adpf"

#include <android/frameworks/adpf/IAdpfService.h>
#include <binder/IServiceManager.h>
#include <log/log.h>

namespace android::frameworks::adpf {

sp<IAdpfService> getService() {
    static std::mutex sMutex;
    static sp<IAdpfService> sService;

    std::lock_guard lock(sMutex);

    if (sService != nullptr) {
        return sService;
    }

    const String16 SERVICE_NAME("adpfservice");
    sp<IBinder> binder = defaultServiceManager()->getService(SERVICE_NAME);
    if (binder == nullptr) {
        ALOGE("failed to get binder");
        return nullptr;
    }

    sService = checked_interface_cast<IAdpfService>(binder);
    if (sService == nullptr) {
        ALOGE("failed to cast to IAdpfService");
        return nullptr;
    }

    ALOGI("returning from getService");
    return sService;
}

} // namespace android::frameworks::adpf


using AdpfServicePointer = android::sp<android::frameworks::adpf::IAdpfService>;

AdpfServicePointer getService(const char* function) {
    auto service = android::frameworks::adpf::getService();
    if (service == nullptr) {
        ALOGE("%s: failed to get service", function);
    }
    return service;
}

template<typename Return>
Return call(const char* function, std::function<Return(const AdpfServicePointer&)> method) {
    if (auto service = getService(function); service != nullptr) {
        return method(service);
    } else {
        return {};
    }
}

template<>
void call(const char* function, std::function<void(const AdpfServicePointer&)> method) {
    if (auto service = getService(function); service != nullptr) {
        method(service);
    }
}

extern "C" {
    int64_t createStage(int* threadIds, uint32_t threadIdsSize, int64_t desiredDurationMicros) {
        ALOGI("%s from Adpf", __FUNCTION__);
        return call<int64_t>(__FUNCTION__, [&](const AdpfServicePointer& service) {
            int64_t stageId = -1;
            service->createStage(std::vector<int>(threadIds, threadIds + threadIdsSize),
                    desiredDurationMicros, &stageId);
            return stageId;
        });
    }

    void destroyStage(int64_t id) {
        ALOGI("%s from Adpf", __FUNCTION__);
        call<void>(__FUNCTION__, [&](const AdpfServicePointer& service) {
            service->destroyStage(id);
        });
    }

    void reportCpuCompletionTime(int64_t id, int64_t actualDurationMicros) {
        ALOGI("%s from Adpf", __FUNCTION__);
        call<void>(__FUNCTION__, [&](const AdpfServicePointer& service) {
            service->reportCpuCompletionTime(id, actualDurationMicros);
        });
    }

    void reportGpuCompletionTime(int64_t id, int64_t actualDurationMicros) {
        ALOGI("%s from Adpf", __FUNCTION__);
        call<void>(__FUNCTION__, [&](const AdpfServicePointer& service) {
            service->reportGpuCompletionTime(id, actualDurationMicros);
        });
    }

    void hintLowLatency(int* threadIds, uint32_t threadIdsSize) {
        ALOGI("%s from Adpf", __FUNCTION__);
        call<void>(__FUNCTION__, [&](const AdpfServicePointer& service) {
            service->hintLowLatency(std::vector<int>(threadIds, threadIds + threadIdsSize));
        });
    }

    void hintLoadChange(int32_t unit, int32_t direction) {
        ALOGI("%s from Adpf", __FUNCTION__);
        call<void>(__FUNCTION__, [&](const AdpfServicePointer& service) {
            service->hintLoadChange(unit, direction);
        });
    }

    void hintMode(int32_t mode, int64_t majorPhase, int64_t minorPhase) {
        ALOGI("%s from Adpf", __FUNCTION__);
        call<void>(__FUNCTION__, [&](const AdpfServicePointer& service) {
            service->hintMode(mode, majorPhase, minorPhase);
        });
    }

    void allowAppSpecificOptimizations(bool enable) {
        ALOGI("%s from Adpf", __FUNCTION__);
        call<void>(__FUNCTION__, [&](const AdpfServicePointer& service) {
            service->allowAppSpecificOptimizations(enable);
        });
    }

    void allowFidelityDegradation(bool enable) {
        ALOGI("%s from Adpf", __FUNCTION__);
        call<void>(__FUNCTION__, [&](const AdpfServicePointer& service) {
            service->allowFidelityDegradation(enable);
        });
    }
}
