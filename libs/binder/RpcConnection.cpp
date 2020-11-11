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

#include <binder/Parcel.h>
#include <binder/Stability.h>

#include "RpcState.h"
#include "RpcWireFormat.h"

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

// FIXME: what else?
#if defined(__GLIBC__)
extern "C" pid_t gettid();
#endif

namespace android {

using base::unique_fd;

RpcConnection::RpcConnection() {
    ALOGE("RpcConnection created %p", this);

    mState = std::make_unique<RpcState>();
}
RpcConnection::~RpcConnection() {
    ALOGE("RpcConnection destroyed %p", this);
}

// FIXME: should accepting server connections be moved here, so the code is
// adjacent to below?
sp<RpcConnection> RpcConnection::responseConnection(unique_fd&& fd) {
    sp<RpcConnection> connection = new RpcConnection;
    {
        // FIXME: move these in general utility - obvi mutex not actually required
        // here
        std::lock_guard<std::mutex> _l (connection->mHoleMutex);
        connection->mServers.push_back(ConnectionHole {
          .fd = std::move(fd),
        });
    }
    return connection;
}

sp<RpcConnection> RpcConnection::connect(const char* path) {
    ALOGI("Connecting on path: %s", path);

    unique_fd serverFd(TEMP_FAILURE_RETRY(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)));
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
    if (0 != ::connect(serverFd.get(), (struct sockaddr *)&addr, sizeof(addr))) {
        ALOGE("Could not connect socket at %s: %s", path, strerror(errno));
    }

    sp<RpcConnection> connection = new RpcConnection;
    {
        std::lock_guard<std::mutex> _l (connection->mHoleMutex);
        connection->mClients.push_back(ConnectionHole {
          .fd = std::move(serverFd),
        });
    }
    return connection;
}

sp<IBinder> RpcConnection::getRootObject() {
    ExclusiveHole hole(this);
    return state()->getRootObject(hole.fd(), this);
}

status_t RpcConnection::transact(const RpcAddress& address, uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) {
    ExclusiveHole hole(this);
    return state()->transact(hole.fd(), address, code, data, this, reply, flags);
}

status_t RpcConnection::sendDecStrong(const RpcAddress& address) {
    ExclusiveHole hole(this);
    return state()->sendDecStrong(hole.fd(), address);
}

void RpcConnection::join() {
    // FIXME: make sure this is a 'server-type' hole
    // FIXME: should delete hole on exit
    // FIXME: implement polling-style access (where only one reader allowed?)
    ExclusiveHole hole(this);
    while(true) {
        status_t error = state()->getAndExecuteCommand(hole.fd(), this);

        if (error != OK) {
            ALOGE("Binder socket thread closing.");
            return;
        }

        ALOGE("Successfully processed command."); // FIXME: spam
    }
}

RpcConnection::ExclusiveHole::ExclusiveHole(const sp<RpcConnection>& connection) : mConnection(connection) {
    // FIXME: sometimes, we want to only do nested transactions
    //        so, we should avoid checking 'client holes'
    pid_t tid = gettid();
    std::lock_guard<std::mutex> _l (mConnection->mHoleMutex);
    for (ConnectionHole& hole : mConnection->mClients) {
        if (hole.exclusiveTid == std::nullopt) {
            hole.exclusiveTid = tid;
            mHole = &hole;
            return;
        }
        if (hole.exclusiveTid == tid) {
            mHole = &hole;
            mReentrant = true;
            return;
        }
    }
    for (ConnectionHole& hole : mConnection->mServers) {
        if (hole.exclusiveTid == std::nullopt) {
            hole.exclusiveTid = tid;
            mHole = &hole;
            return;
        }
        if (hole.exclusiveTid == tid) {
            mHole = &hole;
            mReentrant = true;
            return;
        }
    }
    // FIXME: retry logic/broadcast/notify
    LOG_ALWAYS_FATAL("NO AVAILABLE CONNECTION");
}
RpcConnection::ExclusiveHole::~ExclusiveHole() {
    if (mReentrant) return;

    std::lock_guard<std::mutex> _l (mConnection->mHoleMutex);
    mHole->exclusiveTid = std::nullopt;
}

} // namespace android
