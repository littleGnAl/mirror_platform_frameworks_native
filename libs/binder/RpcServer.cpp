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
#include <binder/Parcel.h>

#include "RpcCommands.h"

namespace android {

using base::unique_fd;

RpcServer::RpcServer() {}
RpcServer::~RpcServer() {}

sp<RpcServer> RpcServer::makeUnixServer(const char* path) {
    // FIXME: add libbase dependency and use unique_serverFd?
    unique_fd serverFd (TEMP_FAILURE_RETRY(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)));
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

    if (0 != TEMP_FAILURE_RETRY(bind(serverFd.get(), (struct sockaddr *)&addr, sizeof(addr)))) {
        ALOGE("Could not bind socket at %s: %s", path, strerror(errno));
        return nullptr;
    }

    if (0 != TEMP_FAILURE_RETRY(listen(serverFd.get(), 1 /*backlog*/))) {
        ALOGE("Could not listen socket at %s: %s", path, strerror(errno));
        return nullptr;
    }

    struct sockaddr_un clientSa;
    socklen_t clientSaLen = sizeof(clientSa);

    unique_fd clientFd(TEMP_FAILURE_RETRY(accept4(serverFd.get(), (struct sockaddr *)&clientSa, &clientSaLen, SOCK_CLOEXEC)));
    if (clientFd < 0) {
        ALOGE("Could not accept4 socket at %s: %s", path, strerror(errno));
        return nullptr;
    }

    // FIXME: save connection information instead of logging it

    sp<RpcServer> server = new RpcServer;
    (void)serverFd.release(); // FIXME: save
    server->mFd = std::move(clientFd);
    return server;
}

RpcServer::BinderAddress RpcServer::addServedBinder(sp<IBinder> binder) {
    BinderAddress address = mConnectionData.binders.size();
    mConnectionData.binders[address] = binder;
    return address;
}

void RpcServer::join() {
    while(true) {
        status_t error = processCommand(mFd, &mConnectionData);

        if (error == NOT_ENOUGH_DATA) {
            ALOGE("Binder socket thread closing.");
            return;
        }

        // FIXME: more error handling
        ALOGE("PROCESSED COMMAND with result: %d", error); // FIXME: spam
    }
}

status_t RpcServer::processCommand(const unique_fd& fd, RpcServer::ConnectionData* connectionData) {
    ALOGE("PROCESSING COMMAND in %d", getpid());

    // FIXME: what's the best way to read from a socket?
    // FIXME: switch to using Parcel to parse the data from the kernel, like
    // IPCThreadState does?
    // FIXME: clean this all up....

    RpcCommand command;
    // FIXME: error handling/synchronization?
    // FIXME: detect incomplete read
    if (0 == TEMP_FAILURE_RETRY(recv(fd.get(), &command, sizeof(command), MSG_WAITALL))) {
        if (errno == 0) {
            return NOT_ENOUGH_DATA; // FIXME
        }
        ALOGE("Error reading rpc command header: %s", strerror(errno));

        return UNKNOWN_ERROR;
    }

    LOG_ALWAYS_FATAL_IF(command.command != RPC_COMMAND_TRANSACT);
    // FIXME: avoid allocating extra size here?
    std::vector<uint8_t> transactionData(command.bodySize);
    // FIXME: detect incomplete read
    if (0 == TEMP_FAILURE_RETRY(recv(fd.get(), transactionData.data(), transactionData.size(), MSG_WAITALL))) {
        if (errno == 0) {
            return NOT_ENOUGH_DATA; // FIXME
        }
        ALOGE("Error reading rpc command body: %s", strerror(errno));
        return UNKNOWN_ERROR;
    }

    // FIXME: check bodySize < sizeof(RpcTransaction)

    RpcTransaction* transaction = reinterpret_cast<RpcTransaction*>(transactionData.data());
    // FIXME: synchronization
    auto it = connectionData->binders.find(transaction->address);
    if (it == connectionData->binders.end()) {
        ALOGE("Unknown binder address %d", transaction->address);
        return UNKNOWN_ERROR;
    }

    Parcel data;
    data.setData(transaction->data, command.bodySize - offsetof(RpcTransaction, data));

    Parcel reply;
    return it->second->transact(transaction->code, data, &reply, transaction->flags);

    // FIXME: send respones
}

status_t RpcServer::processReply(const unique_fd& fd, RpcServer::ConnectionData* data, Parcel* reply) {
    (void) fd;
    (void) data;
    (void) reply;
    return OK;
}

} // namespace android
