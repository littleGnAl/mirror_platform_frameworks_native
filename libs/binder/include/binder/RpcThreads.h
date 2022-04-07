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

#include <android-base/threads.h>

#include <functional>
#include <memory>
#include <thread>

namespace android {

#ifdef BINDER_RPC_SINGLE_THREADED
class RpcMutex {
public:
    void lock() {}
    void unlock() {}
};

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

    template <typename Duration, typename Predicate>
    std::cv_status wait_for(RpcMutexUniqueLock&, const Duration&, Predicate) {
        return std::cv_status::no_timeout;
    }
};

class RpcMaybeThread {
public:
    RpcMaybeThread() : mExecuted(true), mFunc() {}

    template <typename Function, typename... Args>
    RpcMaybeThread(Function&& f, Args&&... args) : mExecuted(false) {
        // std::function requires a copy-constructible closure,
        // so we need to wrap both the function and its arguments
        // in a shared pointer that std::function can copy internally
        struct Vars {
            std::decay_t<Function> f;
            std::tuple<std::decay_t<Args>...> args;

            explicit Vars(Function&& f, Args&&... args)
                  : f(std::move(f)), args(std::move(args)...) {}
        };
        auto vars = std::make_shared<Vars>(std::forward<Function>(f), std::forward<Args>(args)...);
        mFunc = [vars]() { std::apply(std::move(vars->f), std::move(vars->args)); };
    }

    void join() {
        if (mExecuted) {
            return;
        }

        mExecuted = true;
        mFunc();
    }
    void detach() { join(); }

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

private:
    bool mExecuted;
    std::function<void(void)> mFunc;
};

namespace rpc_this_thread {
static inline RpcMaybeThread::id get_id() {
    return RpcMaybeThread::id();
}
} // namespace rpc_this_thread

static inline uint64_t rpcGetThreadId() {
    return 0;
}

static inline void rpcRunThread(RpcMaybeThread& t) {
    t.join();
}
#else  // BINDER_RPC_SINGLE_THREADED
using RpcMutex = std::mutex;
using RpcMutexUniqueLock = std::unique_lock<std::mutex>;
using RpcMutexLockGuard = std::lock_guard<std::mutex>;
using RpcConditionVariable = std::condition_variable;
using RpcMaybeThread = std::thread;
namespace rpc_this_thread = std::this_thread;

static inline uint64_t rpcGetThreadId() {
    return base::GetThreadId();
}

static inline void rpcRunThread(RpcMaybeThread&) {}
#endif // BINDER_RPC_SINGLE_THREADED

} // namespace android
