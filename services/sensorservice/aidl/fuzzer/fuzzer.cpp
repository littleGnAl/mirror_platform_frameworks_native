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
#include <fuzzbinder/random_fd.h>
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

constexpr int32_t kMinValue = 0;
constexpr int32_t kMaxValue = 4096;

int32_t DestroyJavaVM(JavaVM*) {
    return JNI_OK;
}

int32_t AttachCurrentThread(JavaVM*, JNIEnv**, void*) {
    return JNI_OK;
}

int32_t DetachCurrentThread(JavaVM*) {
    return JNI_OK;
}

int32_t GetEnv(JavaVM*, void**, jint) {
    return JNI_OK;
}

int32_t AttachCurrentThreadAsDaemon(JavaVM*, JNIEnv**, void*) {
    return JNI_OK;
}

bool writeCustomParcel(android::Parcel* p, FuzzedDataProvider& provider, uint32_t code) {
    if (code == (uint32_t)(0x00000001) /* createAshmemDirectChannel */) {
        int64_t fdMemSize = provider.ConsumeIntegralInRange<int64_t>(0, 4096);
        std::vector<android::base::unique_fd> fds = android::getRandomFds(&provider);

        // filling the data in the same format as in AParcel APIs
        size_t start_pos = p->dataPosition();
        p->writeInt32(0);
        p->writeInt32(1);
        p->writeDupParcelFileDescriptor(fds.begin()->get());
        p->writeInt64(fdMemSize);
        size_t end_pos = p->dataPosition();
        p->setDataPosition(start_pos);
        p->writeInt32(end_pos - start_pos);
        p->setDataPosition(end_pos);

        p->writeInt64(provider.ConsumeIntegralInRange<int64_t>(0, fdMemSize));
        return true;
    }
    if (code == (uint32_t)(0x00000004) /* getDefaultSensor */) {
        // filling the data in the same format as in AParcel APIs
        // Adding 4 bytes of data - int32_t
        std::vector<uint8_t> data = provider.ConsumeBytes<uint8_t>(4);
        p->write(data.data(), data.size());
        return true;
    }
    return false;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static android::sp<android::ServiceManager> fakeServiceManager = new android::ServiceManager();
    std::call_once(gSmOnce, [&] { setDefaultServiceManager(fakeServiceManager); });
    fakeServiceManager->clear();

    FuzzedDataProvider fdp(data, size);
    android::sp<android::IBinder> binder = android::getRandomBinder(&fdp);
    if (binder == nullptr) {
        // Nothing to do if we get a null binder. It will cause SensorManager to
        // hang while trying to get sensorservice.
        return 0;
    }

    CHECK(android::NO_ERROR == fakeServiceManager->addService(android::String16("sensorservice"),
                                   binder));

    // Adding a dummy instance of JVM to avoid Null Pointer Dereference
    JNIInvokeInterface interface = {nullptr,
                                    nullptr,
                                    nullptr,
                                    &DestroyJavaVM,
                                    &AttachCurrentThread,
                                    &DetachCurrentThread,
                                    &GetEnv,
                                    &AttachCurrentThread};
    JavaVM jvm = {&interface};
    std::shared_ptr<SensorManagerAidl> sensorService =
            ndk::SharedRefBase::make<SensorManagerAidl>(&jvm);
    fuzzService(sensorService->asBinder().get(), std::move(fdp),
                std::bind(&writeCustomParcel, std::placeholders::_1, std::placeholders::_2,
                          std::placeholders::_3));
    return 0;
}
