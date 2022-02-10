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

#define LOG_TAG "dumpstate"

#include "DumpPool.h"

#include <array>
#include <thread>

#include <log/log.h>

#include "dumpstate.h"
#include "DumpstateInternal.h"
#include "DumpstateUtil.h"

namespace android {
namespace os {
namespace dumpstate {

DumpPool::~DumpPool() {
    std::unique_lock lock(lock_);
    if (shutdown_ || threads_.empty()) {
        return;
    }
    while (!tasks_.empty()) tasks_.pop();

    shutdown_ = true;
    condition_variable_.notify_all();
    lock.unlock();

    for (auto& thread : threads_) {
        thread.join();
    }
    threads_.clear();
    MYLOGI("shutdown thread pool\n");
}

void DumpPool::start(int thread_counts) {
    assert(thread_counts > 0);
    assert(threads_.empty());
    MYLOGI("Start thread pool:%d\n", thread_counts);
    shutdown_ = false;
    for (int i = 0; i < thread_counts; i++) {
        threads_.emplace_back(std::thread([=]() {
            setThreadName(pthread_self(), i + 1);
            loop();
        }));
    }
}

template <>
void DumpPool::invokeTask<std::function<void()>>(std::function<void()> dump_func,
        const std::string& duration_title) {
    DurationReporter duration_reporter(duration_title, /*logcat_only =*/true,
            /*verbose =*/false);
    std::invoke(dump_func);
}


void DumpPool::setThreadName(const pthread_t thread, int id) {
    std::array<char, 15> name;
    snprintf(name.data(), name.size(), "dumpstate_%d", id);
    pthread_setname_np(thread, name.data());
}

void DumpPool::loop() {
    std::unique_lock lock(lock_);
    while (!shutdown_) {
        if (tasks_.empty()) {
            condition_variable_.wait(lock);
            continue;
        } else {
            auto task = std::move(tasks_.front());
            tasks_.pop();
            lock.unlock();
            std::invoke(task);
            lock.lock();
        }
    }
}

}  // namespace dumpstate
}  // namespace os
}  // namespace android
