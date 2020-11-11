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

#include <binder/RpcServer.h>
#include <log/log.h>

#include "RpcCommands.h"

namespace android {

RpcServer::RpcServer() {}
RpcServer::~RpcServer() {}

sp<RpcServer> RpcServer::makeUnixServer(const char* path) {
    // FIXME: add libbase dependency and use unique_serverFd?
    int serverFd = TEMP_FAILURE_RETRY(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (serverFd == -1) {
        ALOGE("Could not create socket at %s: %s", path, strerror(errno));
        return nullptr;
    }

    struct sockaddr_un addr = {
        .sun_family = AF_UNIX,
    };
    // FIXME: don't do this at all or use a unix path at all
    unsigned int pathLen = strlen(path) + 1;
    LOG_ALWAYS_FATAL_IF(pathLen > sizeof(addr.sun_path), "%u", pathLen);
    memcpy(addr.sun_path, path, pathLen);

    if (0 != TEMP_FAILURE_RETRY(bind(serverFd, (struct sockaddr *)&addr, sizeof(addr)))) {
        ALOGE("Could not bind socket at %s: %s", path, strerror(errno));
        return nullptr;
    }

    if (0 != TEMP_FAILURE_RETRY(listen(serverFd, 1 /*backlog*/))) {
        ALOGE("Could not listen socket at %s: %s", path, strerror(errno));
        return nullptr;
    }

    struct sockaddr_un clientSa;
    socklen_t clientSaLen = sizeof(clientSa);

    // FIXME: add libbase dependency and use clientFd?
    int clientFd = TEMP_FAILURE_RETRY(accept4(serverFd, (struct sockaddr *)&clientSa, &clientSaLen, SOCK_CLOEXEC));
    if (clientFd < 0) {
        ALOGE("Could not accept4 socket at %s: %s", path, strerror(errno));
        return nullptr;
    }

    // FIXME: save connection information instead of logging it

    sp<RpcServer> server = new RpcServer;
    server->mFd = clientFd;
    return server;
}

RpcServer::BinderAddress RpcServer::addServedBinder(sp<IBinder> binder) {
    BinderAddress address = mBinders.size();
    mBinders[address] = binder;
    return address;
}

void RpcServer::join() {
    char buf[1024];
    ssize_t n;
    while ((n = TEMP_FAILURE_RETRY(read(mFd, &buf[0], sizeof(buf)))) > 0) {
        buf[n] = 0;
        ALOGE("Read this from socket: %s", buf);
    }
}

} // namespace android
