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

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <android/binder_libbinder.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>

using android::OK;
using android::RpcServer;
using android::RpcSession;
using android::status_t;
using android::statusToString;
using android::base::unique_fd;

extern "C" {

bool RunRpcServer(AIBinder* service, unsigned int port) {
    auto server = RpcServer::make();
    server->iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction();
    if (status_t status = server->setupVsockServer(port); status != OK) {
        LOG(ERROR) << "Failed to set up vsock server with port " << port
                   << " error: " << statusToString(status).c_str();
        return false;
    }
    server->setRootObject(AIBinder_toPlatformBinder(service));
    server->join();

    // Shutdown any open sessions since server failed.
    (void)server->shutdown();
    return true;
}

AIBinder* RpcClient(unsigned int cid, unsigned int port) {
    auto session = RpcSession::make();
    if (status_t status = session->setupVsockClient(cid, port); status != OK) {
        LOG(ERROR) << "Failed to set up vsock client with CID " << cid << " and port " << port
                   << " error: " << statusToString(status).c_str();
        return nullptr;
    }
    return AIBinder_fromPlatformBinder(session->getRootObject());
}

AIBinder* RpcPreconnectedClient(int fd) {
    unique_fd ufd(fd);
    auto session = RpcSession::make();
    auto requestFunc = [] {
        // no more connections available for preconnected cases
        return unique_fd{};
    };
    if (status_t status = session->setupPreconnectedClient(std::move(ufd), requestFunc);
        status != OK) {
        LOG(ERROR) << "Failed to set up vsock client with fd " << fd
                   << " error: " << statusToString(status).c_str();
        return nullptr;
    }
    return AIBinder_fromPlatformBinder(session->getRootObject());
}
}
