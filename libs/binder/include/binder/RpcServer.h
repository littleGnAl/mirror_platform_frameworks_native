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

#include <binder/IBinder.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>

#include <unordered_map>

namespace android {

// FIXME: actually support this setup, instead of just one.
// FIXME: document security model
// This represents a server of a pool of connections
class RpcServer : public RefBase {
public:
    // FIXME: make unforgeable, exposeable
    // FIXME: make fixed-size
    // FIXME: best place for definition?
    using BinderAddress = int;

    // FIXME: what's the best way to expose these APIs? One per-type?
    // FIXME: request port numbers from context manager
    // sp<RpcServer> makeVsockServer(unsigned int port);
    static sp<RpcServer> makeUnixServer(const char* path);

    BinderAddress addServedBinder(sp<IBinder> binder);

    // FIXME: add methods (or setup constructors) to modify thread counts
    // status_t setMaxThreads(size_t count);
    // ??? addThread();

    void join();

protected:
    ~RpcServer();
private:
    RpcServer();

    // FIXME: combine with RpcConnection, and make process global
    // FIXME: these should be weak pointers to avoid memory leaks
    std::unordered_map<BinderAddress, sp<IBinder>> mBinders;

    // FIXME: support a list of connctions
    // FIXME: unique_fd to add libbase dep to libbinder?
    int mFd;
};

} // namespace android
