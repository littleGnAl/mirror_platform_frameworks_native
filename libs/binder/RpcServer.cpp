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

    // FIXME: save connection information?
    (void)serverFd.release(); // FIXME: save ?

    sp<RpcServer> server = new RpcServer;
    server->mConnection = RpcConnection::responseConnection(std::move(clientFd));
    return server;
}

void RpcServer::setRootObject(const sp<IBinder>& binder) {
    mConnection->state()->setRootObject(binder);
}

void RpcServer::join() {
    while(true) {
        // FIXME: this is a change in the threading pool model
        // This connection represent a single thread which can serve requests as a
        // response to a thread, so for instance, if we have:
        //
        //     PROC A                PROC B
        //    BINDER 1              BINDER 2
        //    BINDER 3
        //       -------sendBinder--->
        //              to BINDER 2
        //              w/ BINDER 3
        //                          BINDER 3 (ref)
        //
        // In this scenario BINDER 3, since it is read from this data parcel, will
        // inherit this connection, and if PROC B makes a call on BINDER 3, then it
        // will only have a single thread to process it on.
        //
        // This comes with a restriction in one case:
        // PROC B needs to make many calls to BINDER 3
        //
        // In this case, we would actually like to inherit some larger connection to
        // PROC A, either by creating it, or by adopting it by looking up a
        // reference to A.
        //
        // Solutions:
        // - switch connection/server to be a global object per-process
        // - add a function to BpBinder which allows you to create a custom larger
        //   connection for the single binder
        // - ???
        status_t error = mConnection->state()->getAndExecuteCommand(mConnection->mFd, mConnection);

        if (error != OK) {
            ALOGE("Binder socket thread closing.");
            return;
        }

        ALOGE("Successfully processed command."); // FIXME: spam
    }
}

} // namespace android
