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

#include "RpcCommands.h"

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

status_t RpcConnection::transact(int address, uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) {
    (void) address;
    (void) code;
    (void) data;
    (void) reply;
    (void) flags;

    RpcTransaction transaction {
        .address = address,
        .code = code,
        .flags = flags,  // FIXME prune
    };

    // FIXME: save extra copy? with real scatter-gather? :)
    std::vector<uint8_t> transactionData(sizeof(RpcTransaction) + data.dataSize());
    memcpy(transactionData.data() + 0, &transaction, sizeof(RpcTransaction));
    memcpy(transactionData.data() + sizeof(RpcTransaction), data.data(), data.dataSize());

    RpcCommand command {
        .command = RPC_COMMAND_TRANSACT,
        .bodySize = (uint32_t) transactionData.size(), // FIXME: range check
    };

    if (sizeof(RpcCommand) != TEMP_FAILURE_RETRY(send(mFd, &command, sizeof(command), 0))) {
        ALOGE("Failed to send command header: %s", strerror(errno));
        return UNKNOWN_ERROR;
    }

    // FIXME: bad cast
    if ((int)transactionData.size() != TEMP_FAILURE_RETRY(send(mFd, transactionData.data(), transactionData.size(), 0))) {
        ALOGE("Failed to send command body: %s", strerror(errno));
        return UNKNOWN_ERROR;
    }

    ALOGE("FIXME: need to read reply");

    // FIXME: wait for reply

    return OK;
}

} // namespace android
