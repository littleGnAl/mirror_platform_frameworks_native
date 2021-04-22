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

#include "RpcExtras.h"

#include <inttypes.h>

#include "RpcState.h"

namespace android {

void RpcExtras::configure(const sp<IBinder>& rootObject, uint32_t maxThreads) {
    AutoMutex _l(mLock);
    LOG_ALWAYS_FATAL_IF(!mThreads.has_value(),
                        "RpcExtras::configure when thread pool is terminating?!");
    LOG_ALWAYS_FATAL_IF(mServer != nullptr, "Already configured");

    mServer = RpcServer::make();
    mServer->iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction();
    mServer->setRootObject(rootObject);
    mMaxThreads = maxThreads;
}

status_t RpcExtras::addClient(android::base::unique_fd&& clientFd) {
    AutoMutex _l(mLock);
    LOG_ALWAYS_FATAL_IF(!mThreads.has_value(),
                        "RpcExtras::addClient when thread pool is terminating?!");
    if (mThreads->size() >= mMaxThreads) {
        LOG_RPC_DETAIL("RpcExtras::addClient: rejecting because existing %zu >= max %" PRIu32,
                       mThreads->size(), mMaxThreads);
        return NO_INIT;
    }
    auto conn = mServer->addClientConnection();
    auto thread = std::make_unique<RpcConnectionThread>(std::move(conn), std::move(clientFd), this);
    auto threadPtr = thread.get();
    auto [it, inserted] = mThreads->emplace(threadPtr, std::move(thread));
    LOG_ALWAYS_FATAL_IF(!inserted);
    LOG_RPC_DETAIL("RpcExtras::addClient: starting handler thread. #threads = %zu",
                   mThreads->size());
    threadPtr->start();
    return NO_ERROR;
}

void RpcExtras::onThreadTerminate(RpcConnectionThread* thread) {
    AutoMutex _l(mLock);
    if (!mThreads.has_value()) return;
    mThreads->erase(thread);
    LOG_RPC_DETAIL("RpcExtras: Deleted RPC client handler thread. #threads = %zu",
                   mThreads->size());
}

RpcExtras::~RpcExtras() {
    ThreadMap threadsCopy;
    {
        AutoMutex _l(mLock);
        LOG_ALWAYS_FATAL_IF(!mThreads.has_value(),
                            "~RpcExtras terminating a thread pool that has already been "
                            "terminated?!");
        threadsCopy = std::move(*mThreads);
        mThreads = std::nullopt;
    }
    if (!threadsCopy.empty()) {
        // This calls ~RpcConnectionThread on each individual thread, which joins the threads.
        // mLock is not held to avoid deadlock in onThreadTerminate.
        LOG_RPC_DETAIL("~RpcExtras: joining & destroying %zu threads...", threadsCopy.size());
        threadsCopy.clear();
    }
}

void RpcExtras::RpcConnectionThread::start() {
    LOG_ALWAYS_FATAL_IF(mThread != nullptr);
    mThread = std::make_unique<std::thread>([this] {
        LOG_RPC_DETAIL("RpcConnectionThread: handler thread starts handling transactions");
        mConnection->join(std::move(mClientFd));
        LOG_RPC_DETAIL("RpcConnectionThread: connection lost, terminating handler thread");
        mExtras->onThreadTerminate(this);
    });
}

RpcExtras::RpcConnectionThread::~RpcConnectionThread() {
    if (mThread != nullptr && mThread->joinable()) {
        LOG_RPC_DETAIL("~RpcConnectionThread: joining the handler thread...");
        mThread->join();
        LOG_RPC_DETAIL("~RpcConnectionThread: handler thread exited, destroying");
    }
}
} // namespace android
