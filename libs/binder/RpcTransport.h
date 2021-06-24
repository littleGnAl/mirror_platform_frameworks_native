/*
 * Copyright (C) 2021 The Android Open Source Project
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

// Wraps the transport layer of RPC. Implementation may use plain sockets or TLS.

#pragma once

#include <memory>

#include <android-base/unique_fd.h>
#include <binder/RpcSession.h>

namespace android {

class RpcTransportCtx;
class RpcTransport;

// Represents a socket connection. Wrapper of SSL for libbinder usage.
class RpcTransport {
public:
    virtual ~RpcTransport() = default;

    // replacement of ::send(). errno may not be set if TLS is enabled.
    virtual int send(const void *buf, int size) = 0;

    // replacement of ::recv(). errno may not be set if TLS is enabled.
    virtual int recv(void *buf, int size) = 0;

    // replacement of ::recv(MSG_PEEK). errno may not be set if TLS is enabled.
    //
    // Implementation details:
    // - For TLS, this may invoke syscalls and read data from the transport
    // into an internal buffer in userspace. After that, pending() == true.
    // - For raw sockets, this calls ::recv(MSG_PEEK), which leaves the data in the kernel buffer;
    // pending() is always false.
    virtual int peek(void *buf, int size) = 0;

    // Returns true if there are data pending in a userspace buffer that RpcTransport holds.
    //
    // Implementation details:
    // - For TLS, this does not invoke any syscalls or read any data from the
    // transport. This only returns whether there are data pending in the internal buffer in
    // userspace.
    // - For raw sockets, this always returns false.
    virtual bool pending() = 0;

protected:
    explicit RpcTransport(android::base::unique_fd socket) : mSocket(std::move(socket)) {}
    [[nodiscard]] inline android::base::borrowed_fd socketFd() const { return mSocket; }

private:
    friend RpcSession; // For FdTrigger
    friend RpcTransportCtx;
    android::base::unique_fd mSocket;
};

// Wrapper of SSL_CTX for libbinder usage.
class RpcTransportCtx {
public:
    // Create a proper context with TLS enabled or not. Never null.
    static std::unique_ptr<RpcTransportCtx> create(bool tls = false);
    virtual ~RpcTransportCtx() = default;
    // Called after ::accept4() to configure TLS.
    virtual std::unique_ptr<RpcTransport> sslAccept(android::base::unique_fd acceptedFd) = 0;
    // Called after ::connect() to configure TLS.
    virtual std::unique_ptr<RpcTransport> sslConnect(android::base::unique_fd connectedFd) = 0;
};

} // namespace android
