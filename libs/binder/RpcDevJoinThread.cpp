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

#include "RpcDevJoinThread.h"

#include "RpcState.h"

namespace android {

std::unique_ptr<RpcDevJoinThread> RpcDevJoinThread::make(const sp<IBinder>& rootObject,
                                                         android::base::unique_fd socketFd) {
    LOG_ALWAYS_FATAL_IF(rootObject == nullptr, "%s: no root object", __PRETTY_FUNCTION__);
    LOG_ALWAYS_FATAL_IF(!socketFd.ok(), "%s: no socket fd", __PRETTY_FUNCTION__);

    std::unique_ptr<RpcDevJoinThread> ret(new RpcDevJoinThread());
    ret->mRpcServer = RpcServer::make();
    ret->mRpcServer->iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction();
    // Weak ref to avoid circular dependency: BBinder -> RpcDevJoinThread -> RpcServer -X-> BBinder
    ret->mRpcServer->setRootObjectWeak(rootObject);
    ret->mRpcServer->setupExternalServer(std::move(socketFd));

    ret->mThread = std::make_unique<std::thread>(&RpcDevJoinThread::run, ret.get());
    return ret;
}

void RpcDevJoinThread::run() {
    {
        std::lock_guard<std::mutex> lock(mLock);
        if (mShuttingDown) {
            LOG_RPC_DETAIL("%s: not join()-ing because already shutting down", __PRETTY_FUNCTION__);
            return;
        }
    }
    LOG_RPC_DETAIL("%s: RpcServer::join()-ing", __PRETTY_FUNCTION__);
    mRpcServer->join();
    LOG_RPC_DETAIL("%s: RpcServer::join() exits, thread stopping", __PRETTY_FUNCTION__);
}

RpcDevJoinThread::~RpcDevJoinThread() {
    LOG_RPC_DETAIL("%s: shutting down server", __PRETTY_FUNCTION__);
    {
        std::lock_guard<std::mutex> lock(mLock);
        if (!mRpcServer->shutdown()) {
            LOG_RPC_DETAIL("%s: RpcServer::shutdown() does nothing because not joining",
                           __PRETTY_FUNCTION__);
        }
        mShuttingDown = true;
    }
    if (mThread->joinable()) {
        LOG_RPC_DETAIL("%s: joining thread", __PRETTY_FUNCTION__);
        mThread->join();
        LOG_RPC_DETAIL("%s: join() thread exits", __PRETTY_FUNCTION__);
    }
}

} // namespace android
