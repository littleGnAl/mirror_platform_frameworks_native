/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <map>
#include <memory>
#include <thread>

#include <binder/RpcServer.h>
#include <utils/Errors.h>
#include <utils/Mutex.h>
#include <utils/StrongPointer.h>

namespace android {

// The RPC data on a BBinder object.
class RpcExtras {
public:
    // Set max number of threads allowed to be spawned to handle RPC calls. Does not
    // terminate existing threads. Transactions are redirected to // |rootObject|.
    void configure(const sp<IBinder>& rootObject, uint32_t maxThreads);

    // Add a new RPC client. Data is transfered via |clientFd|.
    status_t addClient(android::base::unique_fd&& clientFd);

    // Joins all threads.
    ~RpcExtras();

private:
    class RpcConnectionThread;
    using ThreadMap = std::map<RpcConnectionThread*, std::unique_ptr<RpcConnectionThread>>;
    void onThreadTerminate(RpcConnectionThread* thread);
    // for below objects
    Mutex mLock;
    uint32_t mMaxThreads;
    sp<RpcServer> mServer;
    // The thread pool.
    // Use a map to allow erasing by raw pointer.
    // During ~RpcExtras, this is set to nullopt to indicate that the thread pool is terminating.
    std::optional<ThreadMap> mThreads = std::make_optional<ThreadMap>();
};

class RpcExtras::RpcConnectionThread {
public:
    RpcConnectionThread(sp<RpcConnection>&& connection, android::base::unique_fd&& clientFd,
                        RpcExtras* extras)
          : mConnection(std::move(connection)), mClientFd(std::move(clientFd)), mExtras(extras) {}
    // Joins the thread if it is still running.
    ~RpcConnectionThread();
    void start();

private:
    sp<RpcConnection> mConnection;
    android::base::unique_fd mClientFd;
    RpcExtras* mExtras;
    std::unique_ptr<std::thread> mThread;
};

} // namespace android
