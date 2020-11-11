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

#define LOG_TAG "RpcConnection"

#include <binder/RpcConnection.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <binder/Parcel.h>

namespace android {

RpcConnection::RpcConnection() {}
RpcConnection::~RpcConnection() {}

sp<RpcConnection> RpcConnection::connect(const char* path) {
    ALOGI("Connecting on path: %s", path);

    int serverFd = TEMP_FAILURE_RETRY(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0));
    if (serverFd == -1) {
        ALOGE("Could not create socket at %s: %s", path, strerror(errno));
        return nullptr;
    }

    // FIXME: dupe code with RpcServer
    struct sockaddr_un addr = {
        .sun_family = AF_UNIX,
    };
    // FIXME: don't do this at all or use a unix path at all
    unsigned int pathLen = strlen(path) + 1;
    LOG_ALWAYS_FATAL_IF(pathLen > sizeof(addr.sun_path), "%u", pathLen);
    memcpy(addr.sun_path, path, pathLen);

    // FIXME: save connection information
    if (0 != ::connect(serverFd, (struct sockaddr *)&addr, sizeof(addr))) {
        ALOGE("Could not connect socket at %s: %s", path, strerror(errno));
    }

    sp<RpcConnection> connection = new RpcConnection;
    connection->mFd = serverFd;
    return connection;
}

status_t RpcConnection::transact(int handle, uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) {
    // FIXME: send commands, handle nested commands
    (void) handle;
    (void) code;
    (void) data;
    (void) reply;
    (void) flags;

    const std::string hello = "hello";
    ssize_t ret = send(mFd, hello.c_str(), hello.size(), 0);
    if ((int)ret != (int)hello.size()) {
        ALOGE("Could not send socket, size %d, %s", (int)ret, strerror(errno));
    }

    return OK;
}

} // namespace android
