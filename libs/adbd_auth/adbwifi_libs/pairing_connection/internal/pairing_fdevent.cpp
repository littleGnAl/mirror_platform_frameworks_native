/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
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

#include "pairing_fdevent.h"

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>

#include <adbwifi/fdevent/fdevent.h>
#include <android-base/logging.h>

// This file contains methods to control the fdevent looper state. This fille
// should only be included in the implementation files, or in tests.
namespace adbwifi {
namespace pairing {
namespace internal {

namespace {

std::atomic<bool> sLoopStarted{false};

}  // namespace

// Wait for the fdevent loop
void wait_fdevent_loop_thread() {
    std::mutex mutex;
    std::condition_variable cv;
    std::unique_lock<std::mutex> lock(mutex);
    fdevent::fdevent_run_on_main_thread([&]() {
        std::lock_guard<std::mutex> lock(mutex);
        cv.notify_one();
    });

    cv.wait(lock);
}

// Starts the fdevent loop. This is thread-safe.
void start_fdevent_loop_thread() {
    bool expected = false;
    if (sLoopStarted.compare_exchange_strong(expected, true)) {
        std::thread([]() { fdevent::fdevent_loop(); }).detach();
        wait_fdevent_loop_thread();
    }
}

}  // namespace internal
}  // namespace pairing
}  // namespace adbwifi

