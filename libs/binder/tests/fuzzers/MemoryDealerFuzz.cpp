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

#include <binder/MemoryDealer.h>
#include <fuzzer/FuzzedDataProvider.h>

static constexpr size_t kMaxBufferSize = 10000;
static constexpr size_t kMaxDealerSize = 1024 * 512;
static constexpr size_t kMaxAllocSize = 1024;

namespace android {
// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size > kMaxBufferSize) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    size_t dSize = fdp.ConsumeIntegralInRange<size_t>(0, kMaxDealerSize);
    char* name = nullptr;
    uint32_t flags = fdp.ConsumeIntegral<uint32_t>();
    sp<MemoryDealer> dealer = new MemoryDealer(dSize, name, flags);

    while (fdp.remaining_bytes() > 1) {
        switch (fdp.ConsumeIntegral<uint8_t>() % 5) {
            case 1: {
                dealer->getAllocationAlignment();
                break;
            }
            case 2: {
                dealer->getMemoryHeap();
                break;
            }
            case 3: {
                size_t offset = fdp.ConsumeIntegral<size_t>();
                dealer->deallocate(offset);
                break;
            }
            case 4: {
                std::string randString = fdp.ConsumeRandomLengthString(fdp.remaining_bytes());
                dealer->dump(randString.c_str());
                break;
            }
            case 5: {
                size_t allocSize = fdp.ConsumeIntegralInRange<size_t>(0, kMaxAllocSize);
                sp<IMemory> allocated = dealer->allocate(allocSize);
                // If the allocation was successful, try to write to it
                if (allocated != nullptr && allocated->unsecurePointer() != nullptr) {
                    memset(allocated->unsecurePointer(), 1, allocated->size());
                }
            }
        }
    }

    return 0;
}
} // namespace android
