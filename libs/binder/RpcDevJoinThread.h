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
#include <memory>
#include <mutex>
#include <thread>
#include <utility>

#include <android-base/unique_fd.h>
#include <binder/RpcServer.h>

namespace android {

// Wrapper of a thread that solely calls RpcServer::join().
struct RpcDevJoinThread {
    // Terminates RpcServer::join().
    ~RpcDevJoinThread();

    // Configure RpcServer with |rootObject| and |socketFd|. Starts the
    // join thread.
    static std::unique_ptr<RpcDevJoinThread> make(const sp<IBinder>& rootObject,
                                                  android::base::unique_fd socketFd);

    sp<RpcServer> getRpcServer() const { return mRpcServer; }

private:
    RpcDevJoinThread() = default;
    void run();

    sp<RpcServer> mRpcServer;
    std::unique_ptr<std::thread> mThread;

    std::mutex mLock; // for below
    bool mShuttingDown = false;
};
} // namespace android
