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

#define LOG_TAG "RpcServer"

#include <sys/socket.h>
#include <sys/un.h>

#include <vector>

#include <log/log.h>
#include <binder/RpcServer.h>
#include "RpcState.h"
#include <binder/Parcel.h>

#include "RpcWireFormat.h"

namespace android {

using base::unique_fd;

RpcServer::RpcServer() {}
RpcServer::~RpcServer() {}

sp<RpcServer> RpcServer::make() {
    return new RpcServer;
}

sp<RpcConnection> RpcServer::addClientConnection() {
    auto connection = RpcConnection::make();
    mConnections.push_back(connection);
    return connection;
}

void RpcServer::setRootObject(const sp<IBinder>& binder) {
    // FIXME: move root object to server
    for (auto& connection : mConnections) {
        connection->state()->setRootObject(binder);
    }
}

} // namespace android
