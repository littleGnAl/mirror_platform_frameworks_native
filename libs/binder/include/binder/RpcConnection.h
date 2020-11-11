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

namespace android {

class Parcel;
class RpcServer;
struct RpcWireAddress;
using RpcAddress = std::shared_ptr<RpcWireAddress>; // FIXME: combine

// FIXME: actually support this setup, instead of just one.
// This represents a connection to a set of sockets.
class RpcConnection : public RefBase {
public:
    // This represents a connection for responses, e.g.:
    //
    //     process A serves binder a
    //     process B opens a connection to process A
    //     process B makes binder b and sends it to A
    //     A uses this 'back connection' to send things back to B
    //
    // FIXME: should open up another reverse connection instead?
    // FIXME: this will not handle multi-threading well.
    static sp<RpcConnection> responseConnection(base::unique_fd&& fd);

    // FIXME: what's the best way to expose these APIs? One per-type?
    // FIXME: get connection setup from context manager
    static sp<RpcConnection> connect(const char* path);

    // FIXME: add methods to modify thread counts
    // bool requestAddThread(); ???

    // FIXME: this currently just gets whatever server has address '0' from the
    // server, and we need a different way to do this. In practice, only one
    // process on the host VM (or one per VM) should actually have something
    // available like this, and it should be the service manager.
    // FIXME: document this is the process's root object
    sp<IBinder> getRootObject();

    status_t transact(const RpcAddress& address, uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags);
    status_t sendDecStrong(const RpcAddress& address);

    ~RpcConnection();
private:
    friend RpcServer;

    RpcConnection();

    // FIXME: support a list of fds, representing a pooled connection?
    base::unique_fd mFd;
};

} // namespace android
