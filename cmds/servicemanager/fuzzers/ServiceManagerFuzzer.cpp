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

#include <android-base/hex.h>
#include <fuzzbinder/libbinder_driver.h>
#include <utils/StrongPointer.h>

#include "Access.h"
#include "ServiceManager.h"

using ::android::Access;
using ::android::Parcel;
using ::android::ServiceManager;
using ::android::sp;
using ::android::base::HexString;

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider provider(data, size);
    auto accessPtr = std::make_unique<Access>();
    auto serviceManager = sp<ServiceManager>::make(std::move(accessPtr));

    std::vector<uint8_t> reservedBytes = provider.ConsumeBytes<uint8_t>(8);
    std::cout << "Reserved bytes :" << HexString(reservedBytes.data(), reservedBytes.size())
              << std::endl;

    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    std::cout << "Code :" << code << std::endl;

    uint32_t flag = provider.ConsumeIntegral<uint32_t>();
    std::cout << "Flag :" << flag << std::endl;

    std::vector<uint8_t> parcelData = provider.ConsumeRemainingBytes<uint8_t>();
    std::cout << "Parcel Data :" << HexString(parcelData.data(), parcelData.size()) << std::endl;

    Parcel inputParcel;
    inputParcel.setData(parcelData.data(), parcelData.size());

    Parcel reply;
    serviceManager->transact(code, inputParcel, &reply, flag);

    serviceManager->clear();

    return 0;
}
