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

#include <fuzzer/FuzzedDataProvider.h>
#include <thread>
#include "BlockingQueue.h"

static constexpr size_t kSmallestCapacity = 2;
static constexpr size_t kReallySmallCapacity = 5;
static constexpr size_t kSmallCapacity = 10;
static constexpr size_t kLargeCapacity = 100;

namespace android {

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Queue_AddAndRemove
    {
        size_t capacity = fdp.ConsumeIntegralInRange<size_t>(1, kSmallCapacity);
        BlockingQueue<int32_t> queue(capacity);
        queue.push(fdp.ConsumeIntegral<int32_t>());
        queue.pop();
    }

    // Queue_ReachesCapacity
    {
        size_t capacity = fdp.ConsumeIntegralInRange<size_t>(1, kReallySmallCapacity);
        BlockingQueue<int32_t> queue(capacity);
        size_t numPushes = fdp.ConsumeIntegralInRange<size_t>(0, capacity + 1);
        for (size_t i = 0; i < numPushes; i++) {
            queue.push(fdp.ConsumeIntegral<int32_t>());
        }
    }

    // Queue_isFIFO
    {
        size_t capacity = fdp.ConsumeIntegralInRange<size_t>(1, kSmallCapacity);
        BlockingQueue<int32_t> queue(capacity);
        for (size_t i = 0; i < capacity; i++) {
            queue.push(fdp.ConsumeIntegral<int32_t>());
        }
        for (size_t i = 0; i < capacity; i++) {
            queue.pop();
        }
    }

    // Queue_Clears
    {
        BlockingQueue<int32_t> queue(kSmallestCapacity);
        queue.push(fdp.ConsumeIntegral<int32_t>());
        queue.push(fdp.ConsumeIntegral<int32_t>());
        queue.clear();
        queue.push(fdp.ConsumeIntegral<int32_t>());
        queue.pop();
    }

    // Queue_Erases
    {
        size_t capacity = fdp.ConsumeIntegralInRange<size_t>(1, kReallySmallCapacity);
        BlockingQueue<int32_t> queue(capacity);
        queue.push(fdp.ConsumeIntegral<int32_t>());
        queue.push(fdp.ConsumeIntegral<int32_t>());
        queue.push(fdp.ConsumeIntegral<int32_t>());
        queue.push(fdp.ConsumeIntegral<int32_t>());
        int32_t eraseElement = fdp.ConsumeIntegral<int32_t>();
        queue.erase([&eraseElement](int32_t element) { return eraseElement; });
        for (size_t i = 0; i < queue.size(); i++) {
            queue.pop();
        }
    }

    // Queue_AllowsMultipleThreads
    {
        // large capacity to increase likelihood that threads overlap
        size_t capacity = fdp.ConsumeIntegralInRange<size_t>(1, kLargeCapacity + 15);
        constexpr size_t newCapacity = 100;
        BlockingQueue<int32_t> queue(capacity);
        // Fill queue from a different thread
        std::thread fillQueue([&queue, &fdp]() {
            for (size_t i = 0; i < newCapacity; i++) {
                queue.push(fdp.ConsumeIntegralInRange<int32_t>(0, 10));
            }
        });
        fillQueue.join();
        for (size_t i = 0; i < queue.size(); i++) {
            queue.pop();
        }
    }

    return 0;
}

} // namespace android