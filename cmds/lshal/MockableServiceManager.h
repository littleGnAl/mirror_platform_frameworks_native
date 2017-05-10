/*
 * Copyright (C) 2017 The Android Open Source Project
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

#ifndef FRAMEWORK_NATIVE_CMDS_LSHAL_MOCKABLE_SERVICE_MANAGER_H_
#define FRAMEWORK_NATIVE_CMDS_LSHAL_MOCKABLE_SERVICE_MANAGER_H_

#include <android/hidl/manager/1.0/IServiceManager.h>

namespace android {
namespace lshal {

class MockableServiceManager : public RefBase {
public:
    using IServiceManager = hidl::manager::V1_0::IServiceManager;
    MockableServiceManager() : mServiceManager(nullptr) {
    }
    MockableServiceManager(sp<IServiceManager> serviceManager) : mServiceManager(serviceManager) {
    }
    virtual ~MockableServiceManager() {}
    virtual hardware::Return<void> list(IServiceManager::list_cb _hidl_cb) {
        if (hasImplementation())
            return mServiceManager->list(_hidl_cb);
        return hardware::Void();
    }
    virtual hardware::Return<void> debugDump(IServiceManager::debugDump_cb _hidl_cb) {
        if (hasImplementation())
            return mServiceManager->debugDump(_hidl_cb);
        return hardware::Void();
    }
    virtual hardware::Return<sp<::android::hidl::base::V1_0::IBase>> get(
            const hardware::hidl_string& fqName,
            const hardware::hidl_string& name) {
        if (hasImplementation())
            return mServiceManager->get(fqName, name);
        return nullptr;
    }

    bool hasImplementation() const {
        return mServiceManager != nullptr;
    }

private:
    sp<IServiceManager> mServiceManager;
};

} // namespace lshal
} // namespace android

#endif
