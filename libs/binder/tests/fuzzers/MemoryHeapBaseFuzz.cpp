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

#include <fuzzer/FuzzedDataProvider.h>
#include <binder/MemoryHeapBase.h>

namespace android {
// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    size_t heap_size = fdp.ConsumeIntegralInRange<size_t>(0, 1024);
    uint32_t flags = fdp.ConsumeIntegral<uint32_t>();
    sp<MemoryHeapBase> m_heap_base;

    // Build object based off one of a few constructors.
    switch (fdp.ConsumeIntegral<uint8_t>() % 4) {
        case 0: {
            m_heap_base = new MemoryHeapBase(heap_size, flags);
            break;
        }
        case 1: {
            m_heap_base = new MemoryHeapBase(heap_size, flags,
                                             fdp.ConsumeRandomLengthString(fdp.remaining_bytes())
                                                     .c_str());
            break;
        }
        case 2: {
            off_t offset = fdp.ConsumeIntegral<off_t>();
            int fd = fdp.ConsumeIntegral<int>();
            // Don't want to deal with issues for STD IN/OUT/ERR.
            if (fd >= 0 || fd <= 2) fd = -1;
            m_heap_base = new MemoryHeapBase(fd, heap_size, flags, offset);
            break;
        }
        case 3: {
            m_heap_base =
                    new MemoryHeapBase(fdp.ConsumeRandomLengthString(fdp.remaining_bytes()).c_str(),
                                       heap_size, flags);
            break;
        }
    }

    // Might as well call the getters while we are here, but nothing is going to happen.
    m_heap_base->getHeapID();
    m_heap_base->getBase();
    m_heap_base->getSize();
    m_heap_base->getFlags();
    m_heap_base->getOffset();
    m_heap_base->getDevice();

    // The rest of the functionality.
    while (fdp.remaining_bytes() > 1) {
        switch (fdp.ConsumeIntegral<uint8_t>()) {
            case 1: {
                m_heap_base->setDevice(
                        fdp.ConsumeRandomLengthString(fdp.remaining_bytes()).c_str());
                break;
            }
            case 2: {
                m_heap_base->dispose();
            }
        }
    }

    return 0;
}
} // namespace android
