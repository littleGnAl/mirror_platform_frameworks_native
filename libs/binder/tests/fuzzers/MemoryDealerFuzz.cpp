/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <MemoryDealerFuzzFunctions.h>
#include <binder/MemoryDealer.h>
#include <commonFuzzHelpers.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>

namespace android {
// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > kMaxBufferSize) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    size_t dSize = fdp.ConsumeIntegralInRange<size_t>(0, kMaxDealerSize);
    std::string name = fdp.ConsumeRandomLengthString(fdp.remaining_bytes());
    uint32_t flags = fdp.ConsumeIntegral<uint32_t>();
    sp<MemoryDealer> dealer = new MemoryDealer(dSize, name.c_str(), flags);

    while (fdp.remaining_bytes() > 0) {
        callArbitraryFunction(&fdp, gMemoryDealerOperations, dealer);
    }

    kFreeList.clear();
    return 0;
}
} // namespace android
