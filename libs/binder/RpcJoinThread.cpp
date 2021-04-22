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

#include "RpcJoinThread.h"

#include "RpcState.h"

namespace android {

status_t RpcJoinThread::initialize(const sp<IBinder>& rootObject, size_t maxRpcThreads,
                                   android::base::unique_fd socketFd) {
    if (rootObject.get() == nullptr) {
        ALOGE("RpcJoinThread is useless without root object");
        return BAD_VALUE;
    }
    if (maxRpcThreads == 0) {
        ALOGE("RpcJoinThread is useless without threads");
        return BAD_VALUE;
    }

    if (!socketFd.ok()) {
        ALOGE("No socket FD provided.");
        return BAD_VALUE;
    }

    LOG_ALWAYS_FATAL_IF(mRpcServer != nullptr, "already initialized");
    LOG_ALWAYS_FATAL_IF(mThread != nullptr, "join thread was already started?!");

    mRpcServer = RpcServer::make();
    mRpcServer->iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction();
    // Weak ref to avoid circular dependency: BBinder -> RpcJoinThread -> RpcServer -X-> BBinder
    mRpcServer->setRootObjectWeak(rootObject);
    mRpcServer->setupExternalServer(std::move(socketFd));
    mRpcServer->setMaxThreads(static_cast<size_t>(maxRpcThreads));

    mThread = std::make_unique<std::thread>(&RpcJoinThread::run, this);
    return OK;
}

void RpcJoinThread::setMaxThreads(size_t maxRpcThreads) {
    mRpcServer->setMaxThreads(static_cast<size_t>(maxRpcThreads));
}

void RpcJoinThread::run() {
    LOG_RPC_DETAIL("%s: RpcServer::join()-ing", __PRETTY_FUNCTION__);
    mRpcServer->join();
    LOG_RPC_DETAIL("%s: RpcServer::join() exits, thread stopping", __PRETTY_FUNCTION__);
}

RpcJoinThread::~RpcJoinThread() {
    if (mRpcServer) {
        LOG_RPC_DETAIL("%s: shutting down server", __PRETTY_FUNCTION__);
        (void)mRpcServer->shutdown();
    }
    if (mThread.get() && mThread->joinable()) {
        LOG_RPC_DETAIL("%s: joining thread", __PRETTY_FUNCTION__);
        mThread->join();
        LOG_RPC_DETAIL("%s: join() thread exits", __PRETTY_FUNCTION__);
    }
}

} // namespace android
