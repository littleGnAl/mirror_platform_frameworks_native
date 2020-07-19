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

namespace android {
// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    uint32_t count = fdp.ConsumeIntegralInRange<uint32_t>(1, 1024);
    size_t d_size = fdp.ConsumeIntegralInRange<size_t>(1, 1024);
    char* name = nullptr;
    uint32_t flags = fdp.ConsumeIntegral<uint32_t>();
    sp<MemoryDealer> dealer = new MemoryDealer(d_size, name, flags);

    while (fdp.remaining_bytes() > 1) {
        if (count == 0) break;
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
                std::string rand_str = fdp.ConsumeRandomLengthString(fdp.remaining_bytes());
                const char* what = rand_str.c_str();
                dealer->dump(what);
                break;
            }
            case 5: {
                d_size = fdp.ConsumeIntegralInRange<size_t>(0, 1024);
                dealer->allocate(d_size);
            }
        }

        count--;
    }

    return 0;
}
} // namespace android
