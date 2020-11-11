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
#pragma once

#include <android-base/unique_fd.h>
#include <binder/IBinder.h>
#include <utils/RefBase.h>
#include <utils/Errors.h>

#include <optional>
#include <vector>

namespace android {

class Parcel;
class RpcServer;
struct RpcWireAddress;
class RpcState;
using RpcAddress = std::shared_ptr<RpcWireAddress>; // FIXME: combine

/**
 * This represents a multi-threaded/multi-socket connection between a client
 * and a server.
 */
class RpcConnection : public RefBase {
public:
    // This represents a connection for responses, e.g.:
    //
    //     process A serves binder a
    //     process B opens a connection to process A
    //     process B makes binder b and sends it to A
    //     A uses this 'back connection' to send things back to B
    //
    static sp<RpcConnection> responseConnection(base::unique_fd&& fd);

    // FIXME: what's the best way to expose these APIs? One per-type?
    // FIXME: get connection setup from context manager
    static sp<RpcConnection> connect(const char* path);

    // FIXME: add methods to modify thread counts
    // bool requestAddThread(); ???

    // FIXME: document this is the process's root object
    sp<IBinder> getRootObject();

    status_t transact(const RpcAddress& address, uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags);
    status_t sendDecStrong(const RpcAddress& address);

    // Joins this connection, assuming that a server has been setup here.
    // FIXME: document return, maybe rename
    void join();

    ~RpcConnection();

    // FIXME: only needed for testing (Parcel should use new APIs here)
    const std::unique_ptr<RpcState>& state() { return mState; }
private:
    RpcConnection();

    struct ConnectionHole {
        base::unique_fd fd;
        // whether this or another thread is currently using this fd to make
        // or receive transactions.
        std::optional<pid_t> exclusiveTid;
    };

    // RAAI object for connection hole
    class ExclusiveHole {
    public:
       explicit ExclusiveHole(const sp<RpcConnection>& connection);
       ~ExclusiveHole();
       const base::unique_fd& fd() { return mHole->fd; }
    private:
       sp<RpcConnection> mConnection;
       // FIXME: have to be too careful not moving the object around
       // owned by connection
       ConnectionHole* mHole = nullptr;
       // whether this is being used for a nested transaction (being on the same
       // thread guarantees we won't write in the middle of a message, the way
       // the wire protocol is constructed guarantees this is safe).
       bool mReentrant = false;
    };

    // On the other side of a connection, for every mClient here, there should
    // be an mServer on the other side (and vice versa).
    //
    // For the simplest connection, a single server with one client, you would
    // have:
    //  - the server has a single 'mServer' and a thread listening on this
    //  - the client has a single 'mClients' and makes calls to this
    //  - here, when the client makes a call, the server can call back into it
    //    (nested calls), but outside of this, the client will only ever read
    //    calls from the server when it makes a call itself.
    //
    // For a more complicated case, the client might itself open up a thread to
    // serve calls to the server at all times (e.g. if it hosts a callback)
    //
    // FIXME: document/add way to add additional threads
    // FIXME: logs/warnings need to be added - it needs to be hard to
    //        accidentally create enough threads
    // FIXME: resource sharing - for servers, should we have single threads work
    //        multiple connectoins? can we support that w/o much additional
    //        work?

    std::unique_ptr<RpcState> mState;

    std::mutex mHoleMutex;
    std::vector<ConnectionHole> mClients;
    std::vector<ConnectionHole> mServers;
};

} // namespace android
