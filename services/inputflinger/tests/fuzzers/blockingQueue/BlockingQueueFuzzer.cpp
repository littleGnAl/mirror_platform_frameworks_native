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

#define SMALLEST_CAPACITY 2
#define REALLY_SMALL_CAPACITY 5
#define SMALL_CAPACITY 10
#define LARGE_CAPACITY 100

namespace android {

extern "C" int LLVMFuzzerTestOneInput(uint8_t *data, size_t size) {
    FuzzedDataProvider tester(data, size);
    // Queue_AddAndRemove
    size_t capacity = tester.ConsumeIntegralInRange(1, SMALL_CAPACITY);
    BlockingQueue<int32_t> queue(capacity);
    queue.push(tester.ConsumeIntegral<int32_t>());
    queue.pop();

    // Queue_ReachesCapacity
    capacity = tester.ConsumeIntegralInRange(1, REALLY_SMALL_CAPACITY);
    BlockingQueue<int32_t> newQueue(capacity);
    newQueue.push(tester.ConsumeIntegral<int32_t>());
    newQueue.push(tester.ConsumeIntegral<int32_t>());
    newQueue.push(tester.ConsumeIntegral<int32_t>());
    newQueue.push(tester.ConsumeIntegral<int32_t>());

    // Queue_isFIFO
    capacity = tester.ConsumeIntegralInRange(1, SMALL_CAPACITY);
    BlockingQueue<int32_t> anotherQueue(capacity);
    for (size_t i = 0; i < capacity; i++) {
        anotherQueue.push(tester.ConsumeIntegral<int32_t>());
    }

    for (size_t i = 0; i < capacity; i++) {
        anotherQueue.pop();
    }

    // Queue_Clears
    BlockingQueue<int32_t> aqueue(SMALLEST_CAPACITY);
    aqueue.push(tester.ConsumeIntegral<int32_t>());
    aqueue.push(tester.ConsumeIntegral<int32_t>());
    aqueue.clear();
    aqueue.push(tester.ConsumeIntegral<int32_t>());

    aqueue.pop();

    // Queue_Erases
    capacity = tester.ConsumeIntegralInRange(1, REALLY_SMALL_CAPACITY);
    BlockingQueue<int32_t> bqueue(capacity);
    bqueue.push(tester.ConsumeIntegral<int32_t>());
    bqueue.push(tester.ConsumeIntegral<int32_t>());
    bqueue.push(tester.ConsumeIntegral<int32_t>());
    bqueue.push(tester.ConsumeIntegral<int32_t>());
    // Erase elements 2 and 4
    int32_t eraseElement = tester.ConsumeIntegral<int32_t>();
    bqueue.erase([&eraseElement](int32_t element) { return eraseElement; });
    // Should no longer receive elements 2 and 4
    for (size_t i = 0; i < bqueue.size(); i++) { // let's not go crazy with pops
        bqueue.pop();
    }
    // Queue_AllowsMultipleThreads
    capacity =
            tester.ConsumeIntegralInRange(1,
                                          LARGE_CAPACITY + 15); // large capacity to increase
                                                                // likelihood that threads overlap
    constexpr size_t newCapacity =
            100; // to avoid errors when compiled, should be the same as capacity
    BlockingQueue<int32_t> cqueue(capacity);
    // Fill queue from a different thread
    std::thread fillQueue([&cqueue, &tester]() {
        for (size_t i = 0; i < newCapacity; i++) {
            cqueue.push(tester.ConsumeIntegralInRange<int32_t>(0, 10));
        }
    });
    fillQueue.join();
    // Make sure all elements are received in correct order
    for (size_t i = 0; i < cqueue.size(); i++) {
        cqueue.pop(); // static_cast<int32_t>(i) & queue.pop should equal each other
    }
    return 0;
}

} // namespace android