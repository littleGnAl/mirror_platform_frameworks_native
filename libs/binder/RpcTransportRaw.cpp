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

#define LOG_TAG "RpcRawTransport"
#include <log/log.h>

#include <poll.h>

#include <binder/RpcTransportRaw.h>

#include "FdTrigger.h"
#include "RpcState.h"
#include "RpcTransportUtils.h"

namespace android {

namespace {

// RpcTransport with TLS disabled.
class RpcTransportRaw : public RpcTransport {
public:
    explicit RpcTransportRaw(android::base::unique_fd socket) : mSocket(std::move(socket)) {}
    status_t pollRead(void) override {
        uint8_t buf;
        ssize_t ret = TEMP_FAILURE_RETRY(
                ::recv(mSocket.get(), &buf, sizeof(buf), MSG_PEEK | MSG_DONTWAIT));
        if (ret < 0) {
            int savedErrno = errno;
            if (savedErrno == EAGAIN || savedErrno == EWOULDBLOCK) {
                return WOULD_BLOCK;
            }

            LOG_RPC_DETAIL("RpcTransport poll(): %s", strerror(savedErrno));
            return -savedErrno;
        } else if (ret == 0) {
            return DEAD_OBJECT;
        }

        return OK;
    }

    status_t interruptableWriteFully(
            FdTrigger* fdTrigger, iovec* iovs, int niovs,
            const std::optional<android::base::function_ref<status_t()>>& altPoll) override {
        auto writeFn = [](int fd, iovec* iovs, size_t niovs) {
            msghdr msg{
                    .msg_iov = iovs,
                    // posix uses int, glibc uses size_t.  niovs is a
                    // non-negative int and can be cast to either.
                    .msg_iovlen = static_cast<decltype(msg.msg_iovlen)>(niovs),
            };
            return TEMP_FAILURE_RETRY(sendmsg(fd, &msg, MSG_NOSIGNAL));
        };
        return interruptableReadOrWrite(mSocket.get(), fdTrigger, iovs, niovs, writeFn, "sendmsg",
                                        POLLOUT, altPoll);
    }

    status_t interruptableReadFully(
            FdTrigger* fdTrigger, iovec* iovs, int niovs,
            const std::optional<android::base::function_ref<status_t()>>& altPoll) override {
        auto readFn = [](int fd, iovec* iovs, size_t niovs) {
            msghdr msg{
                    .msg_iov = iovs,
                    // posix uses int, glibc uses size_t.  niovs is a
                    // non-negative int and can be cast to either.
                    .msg_iovlen = static_cast<decltype(msg.msg_iovlen)>(niovs),
            };
            return TEMP_FAILURE_RETRY(recvmsg(fd, &msg, MSG_NOSIGNAL));
        };
        return interruptableReadOrWrite(mSocket.get(), fdTrigger, iovs, niovs, readFn, "recvmsg",
                                        POLLIN, altPoll);
    }

private:
    base::unique_fd mSocket;
};

// RpcTransportCtx with TLS disabled.
class RpcTransportCtxRaw : public RpcTransportCtx {
public:
    std::unique_ptr<RpcTransport> newTransport(android::base::unique_fd fd, FdTrigger*) const {
        return std::make_unique<RpcTransportRaw>(std::move(fd));
    }
    std::vector<uint8_t> getCertificate(RpcCertificateFormat) const override { return {}; }
};

} // namespace

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryRaw::newServerCtx() const {
    return std::make_unique<RpcTransportCtxRaw>();
}

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryRaw::newClientCtx() const {
    return std::make_unique<RpcTransportCtxRaw>();
}

const char *RpcTransportCtxFactoryRaw::toCString() const {
    return "raw";
}

std::unique_ptr<RpcTransportCtxFactory> RpcTransportCtxFactoryRaw::make() {
    return std::unique_ptr<RpcTransportCtxFactoryRaw>(new RpcTransportCtxFactoryRaw());
}

} // namespace android
