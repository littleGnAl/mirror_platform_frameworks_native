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
#pragma once

#include <pthread.h>

#include <thread>

namespace android {

#ifdef BINDER_RPC_NO_THREADS
class RpcMutex {};

class RpcMutexUniqueLock {
public:
    RpcMutexUniqueLock(RpcMutex&) {}
    void unlock() {}
};

class RpcMutexLockGuard {
public:
    RpcMutexLockGuard(RpcMutex&) {}
};

class RpcConditionVariable {
public:
    void notify_one() {}
    void notify_all() {}

    void wait(RpcMutexUniqueLock&) {}

    template <typename Predicate>
    void wait(RpcMutexUniqueLock&, Predicate) {}

    template <typename Duration>
    std::cv_status wait_for(RpcMutexUniqueLock&, const Duration&) {
        return std::cv_status::no_timeout;
    }
};

class RpcThread {
public:
    RpcThread() {}

    template <typename Function, typename... Args>
    RpcThread(Function&& f, Args&&... args) {
        (void)f(std::forward<Args>(args)...);
    }

    void join() {}
    void detach() {}

    class id {
    public:
        bool operator==(const id&) const { return true; }
        bool operator!=(const id&) const { return false; }
        bool operator<(const id&) const { return false; }
        bool operator<=(const id&) const { return true; }
        bool operator>(const id&) const { return false; }
        bool operator>=(const id&) const { return true; }
    };

    id get_id() const { return id(); }
};

namespace rpc_this_thread {
static inline RpcThread::id get_id() {
    return RpcThread::id();
}
} // namespace rpc_this_thread
#else
using RpcMutex = std::mutex;
using RpcMutexUniqueLock = std::unique_lock<std::mutex>;
using RpcMutexLockGuard = std::lock_guard<std::mutex>;
using RpcConditionVariable = std::condition_variable;
using RpcThread = std::thread;
namespace rpc_this_thread = std::this_thread;
#endif

} // namespace android
