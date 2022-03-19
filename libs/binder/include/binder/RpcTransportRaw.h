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

// Wraps the transport layer of RPC. Implementation uses plain sockets.
// Note: don't use directly. You probably want newServerRpcTransportCtx / newClientRpcTransportCtx.

#pragma once

#include <poll.h>
#include <memory>

#include <binder/RpcTransport.h>

namespace android {

// RpcTransport with TLS disabled.
class RpcTransportRaw : public RpcTransport {
public:
    explicit RpcTransportRaw(android::base::unique_fd socket) : mSocket(std::move(socket)) {}
    status_t pollRead(void) override;

    status_t interruptableWriteFully(FdTrigger* fdTrigger, iovec* iovs, int niovs,
                                     const std::function<status_t()>& altPoll) override {
        return interruptableReadOrWrite(fdTrigger, iovs, niovs, socketWriteVec, "sendmsg", POLLOUT,
                                        altPoll);
    }

    status_t interruptableReadFully(FdTrigger* fdTrigger, iovec* iovs, int niovs,
                                    const std::function<status_t()>& altPoll) override {
        return interruptableReadOrWrite(fdTrigger, iovs, niovs, socketReadVec, "recvmsg", POLLIN,
                                        altPoll);
    }

protected:
    status_t interruptableReadOrWrite(
            FdTrigger* fdTrigger, iovec* iovs, int niovs,
            const std::function<ssize_t(int, iovec*, int)>& sendOrReceiveFun, const char* funName,
            int16_t event, const std::function<status_t()>& altPoll);

    // Wrapper around sendmsg with the signature of writev.
    static ssize_t socketWriteVec(int fd, iovec* iovs, int niovs) {
        msghdr msg{
                .msg_iov = iovs,
                // posix uses int, glibc uses size_t.  niovs is a
                // non-negative int and can be cast to either.
                .msg_iovlen = static_cast<decltype(msg.msg_iovlen)>(niovs),
        };
        return sendmsg(fd, &msg, MSG_NOSIGNAL);
    }

    // Wrapper around recvmsg with the signature of readv.
    static ssize_t socketReadVec(int fd, iovec* iovs, int niovs) {
        msghdr msg{
                .msg_iov = iovs,
                // posix uses int, glibc uses size_t.  niovs is a
                // non-negative int and can be cast to either.
                .msg_iovlen = static_cast<decltype(msg.msg_iovlen)>(niovs),
        };
        return recvmsg(fd, &msg, MSG_NOSIGNAL);
    }

    base::unique_fd mSocket;
};

// RpcTransportRaw for files.
class RpcTransportRawFile : public RpcTransportRaw {
public:
    explicit RpcTransportRawFile(android::base::unique_fd socket) : RpcTransportRaw(std::move(socket)) {}

    status_t interruptableWriteFully(FdTrigger* fdTrigger, iovec* iovs, int niovs,
                                     const std::function<status_t()>& altPoll) override {
        return interruptableReadOrWrite(fdTrigger, iovs, niovs, writev, "writev", POLLOUT,
                                        altPoll);
    }

    status_t interruptableReadFully(FdTrigger* fdTrigger, iovec* iovs, int niovs,
                                    const std::function<status_t()>& altPoll) override {
        return interruptableReadOrWrite(fdTrigger, iovs, niovs, readv, "readv", POLLIN,
                                        altPoll);
    }
};

// RpcTransportCtxFactory with TLS disabled.
class RpcTransportCtxFactoryRaw : public RpcTransportCtxFactory {
public:
    static std::unique_ptr<RpcTransportCtxFactory> make();

    std::unique_ptr<RpcTransportCtx> newServerCtx() const override;
    std::unique_ptr<RpcTransportCtx> newClientCtx() const override;
    const char* toCString() const override;

private:
    RpcTransportCtxFactoryRaw() = default;
};

class RpcTransportCtxFactoryRawFile : public RpcTransportCtxFactory {
public:
    static std::unique_ptr<RpcTransportCtxFactory> make();

    std::unique_ptr<RpcTransportCtx> newServerCtx() const override;
    std::unique_ptr<RpcTransportCtx> newClientCtx() const override;
    const char* toCString() const override;

private:
    RpcTransportCtxFactoryRawFile() = default;
};

} // namespace android
