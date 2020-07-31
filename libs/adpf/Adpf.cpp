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

extern "C" {
    void permitFidelityDegradation(bool enable) {
        ALOGI("%s from Adpf", __FUNCTION__);

        auto service = android::frameworks::adpf::getService();
        if (service == nullptr) {
            ALOGE("%s: failed to get service", __FUNCTION__);
            return;
        }

        service->permitFidelityDegradation(enable);
    }
}
