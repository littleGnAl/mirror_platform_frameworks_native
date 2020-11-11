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

sp<RpcConnection> RpcConnection::make() {
    return new RpcConnection;
}

bool RpcConnection::addUnixDomainServer(const char* path) {
    unique_fd serverFd (TEMP_FAILURE_RETRY(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)));
    if (serverFd == -1) {
        ALOGE("Could not create socket at %s: %s", path, strerror(errno));
        return false;
    }

    struct sockaddr_un addr = {
        .sun_family = AF_UNIX,
    };

    unsigned int pathLen = strlen(path) + 1;
    LOG_ALWAYS_FATAL_IF(pathLen > sizeof(addr.sun_path), "%u", pathLen);
    memcpy(addr.sun_path, path, pathLen);

    if (0 != TEMP_FAILURE_RETRY(bind(serverFd.get(), (struct sockaddr *)&addr, sizeof(addr)))) {
        ALOGE("Could not bind socket at %s: %s", path, strerror(errno));
        return false;
    }

    if (0 != TEMP_FAILURE_RETRY(listen(serverFd.get(), 1 /*backlog*/))) {
        ALOGE("Could not listen socket at %s: %s", path, strerror(errno));
        return false;
    }

    addServer(std::move(serverFd));
    return true;
}

bool RpcConnection::addUnixDomainClient(const char* path) {
    ALOGI("Connecting on path: %s", path);

    unique_fd serverFd(TEMP_FAILURE_RETRY(socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0)));
    if (serverFd == -1) {
        ALOGE("Could not create socket at %s: %s", path, strerror(errno));
        return false;
    }

    struct sockaddr_un addr = {
        .sun_family = AF_UNIX,
    };

    unsigned int pathLen = strlen(path) + 1;
    LOG_ALWAYS_FATAL_IF(pathLen > sizeof(addr.sun_path), "%u", pathLen);
    memcpy(addr.sun_path, path, pathLen);

    if (0 != ::connect(serverFd.get(), (struct sockaddr *)&addr, sizeof(addr))) {
        ALOGE("Could not connect socket at %s: %s", path, strerror(errno));
        return false;
    }

    addClient(std::move(serverFd));
    return true;
}

sp<IBinder> RpcConnection::getRootObject() {
    ExclusiveSocket socket(this);
    return state()->getRootObject(socket.fd(), this);
}

status_t RpcConnection::transact(const RpcAddress& address,
                                 uint32_t code,
                                 const Parcel& data,
                                 Parcel* reply,
                                 uint32_t flags) {
    ExclusiveSocket socket(this);
    return state()->transact(socket.fd(), address, code, data, this, reply, flags);
}

status_t RpcConnection::sendDecStrong(const RpcAddress& address) {
    ExclusiveSocket socket(this);
    return state()->sendDecStrong(socket.fd(), address);
}

void RpcConnection::join() {
    // FIXME: make sure this is a 'server-type' socket
    // FIXME: should delete socket on exit
    // FIXME: implement polling-style access (where only one reader allowed?)
    ExclusiveSocket socket(this);

    // FIXME: timeouts

    struct sockaddr_un clientSa;
    socklen_t clientSaLen = sizeof(clientSa);

    unique_fd clientFd(TEMP_FAILURE_RETRY(
        accept4(socket.fd().get(), (struct sockaddr *)&clientSa, &clientSaLen, SOCK_CLOEXEC)));
    if (clientFd < 0) {
        // FIXME: pipe around connection information
        ALOGE("Could not accept4 socket: %s", strerror(errno));
        return;
    }

    ALOGE("FD %d is accepted as %d", socket.fd().get(), clientFd.get()); // pardon the poor parlance

    // FIXME: should not reuse data structure unique_fd
    {
        std::lock_guard<std::mutex> _l(mSocketMutex);
        socket.socket()->fd = std::move(clientFd);
    }

    while(true) {
        status_t error = state()->getAndExecuteCommand(socket.fd(), this);

        if (error != OK) {
            ALOGE("Binder socket thread closing.");
            return;
        }

        ALOGE("Successfully processed command."); // FIXME: spam
    }

    // FIXME: cleanup state
}

void RpcConnection::setForServer(const wp<RpcServer>& server) {
    mForServer = server;
}

wp<RpcServer> RpcConnection::server() {
    return mForServer;
}

void RpcConnection::addClient(base::unique_fd&& fd) {
    std::lock_guard<std::mutex> _l (mSocketMutex);
    mClients.push_back(ConnectionSocket {
        .fd = std::move(fd),
    });

}

void RpcConnection::addServer(base::unique_fd&& fd) {
    std::lock_guard<std::mutex> _l (mSocketMutex);
    mServers.push_back(ConnectionSocket {
        .fd = std::move(fd),
    });
}

RpcConnection::ExclusiveSocket::ExclusiveSocket(const sp<RpcConnection>& connection)
  : mConnection(connection) {
    // FIXME: sometimes, we want to only do nested transactions
    //        so, we should avoid checking 'client sockets'
    // FIXME: needs right oneway queueing behavior, and comparison test w/
    //        regular binder
    pid_t tid = gettid();
    std::unique_lock<std::mutex> _l (mConnection->mSocketMutex);

    // FIXME: handle potential live lock
    // We have the choice here to be selfish and take an available thread, even
    // if there is a thread waiting for one. By being selfish, we avoid a
    // a context switch. However, this also means that a selfish calling thread
    // might drown out calls from another thread.

    mConnection->mWaitingThreads++;
    while (true) {
        ConnectionSocket* exclusive = nullptr;
        ConnectionSocket* available = nullptr;

        findSocket(tid, exclusive, available, mConnection->mClients);
        findSocket(tid, exclusive, available, mConnection->mServers);

        if (exclusive != nullptr) {
            mSocket = exclusive;
            mReentrant = true;
            break;
        } else if (available != nullptr) {
            mSocket = available;
            mSocket->exclusiveTid = tid;
            break;
        }

        // FIXME: log
        mConnection->mSocketCv.wait(_l);
    }
    mConnection->mWaitingThreads--;
}

void RpcConnection::ExclusiveSocket::findSocket(
        pid_t tid,
        ConnectionSocket*& exclusive,
        ConnectionSocket*& available,
        std::vector<ConnectionSocket>& sockets) {

    if (exclusive) return; // consistent with break below

    for (ConnectionSocket& socket : sockets) {
        // take first available connection (intuition = caching)
        if (!available && socket.exclusiveTid == std::nullopt) {
            available = &socket;
            continue;
        }

        // though, prefer to take connection which is already inuse by this thread
        // (nested transactions)
        if (socket.exclusiveTid == tid) {
            exclusive = &socket;
            break; // consistent with return above
        }
    }
}

RpcConnection::ExclusiveSocket::~ExclusiveSocket() {
    // reentrant use of a connection means something less deep in the call stack
    // is using this fd, and it retains the right to it. So, we don't give up
    // exclusive ownership, and no thread is freed.
    if (!mReentrant) {
        std::unique_lock<std::mutex> _l (mConnection->mSocketMutex);
        mSocket->exclusiveTid = std::nullopt;
        if (mConnection->mWaitingThreads > 0) {
            _l.unlock();
            mConnection->mSocketCv.notify_one();
        }
    }
}

} // namespace android
