/*
 * Copyright (C) 2022 The Android Open Source Project
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
#include <fuzzbinder/libbinder_ndk_driver.h>
#include <fuzzer/FuzzedDataProvider.h>

#include <ServiceManager.h>
#include <android-base/logging.h>
#include <android/binder_interface_utils.h>
#include <fuzzbinder/random_binder.h>
#include <sensorserviceaidl/SensorManagerAidl.h>

using android::fuzzService;
using android::frameworks::sensorservice::implementation::SensorManagerAidl;
using ndk::SharedRefBase;

[[clang::no_destroy]] static std::once_flag gSmOnce;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static android::sp<android::IServiceManager> fakeServiceManager = new android::ServiceManager();
    std::call_once(gSmOnce, [&] { setDefaultServiceManager(fakeServiceManager); });
    FuzzedDataProvider fdp(data, size);
    fakeServiceManager->addService(android::String16("sensorservice"),
                                   android::getRandomBinder(&fdp));
    std::shared_ptr<SensorManagerAidl> sensorService =
            ndk::SharedRefBase::make<SensorManagerAidl>(nullptr);

    fuzzService(sensorService->asBinder().get(), std::move(fdp));

    return 0;
}
