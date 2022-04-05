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

#define LOG_TAG "RpcTrustyTransport"

#include <binder/RpcSession.h>
#include <binder/RpcTransportTrusty.h>
#include <log/log.h>
#include <poll.h>
#include <trusty/tipc.h>

#include "FdTrigger.h"
#include "RpcState.h"

using android::base::Error;
using android::base::Result;

namespace android {

namespace {

// RpcTransport for Trusty.
class RpcTransportTrusty : public RpcTransport {
public:
    explicit RpcTransportTrusty(android::base::unique_fd socket) : mSocket(std::move(socket)) {}

    status_t pollRead() override {
        // Trusty IPC device is not a socket, so MSG_PEEK is not available
        pollfd pfd{.fd = mSocket.get(), .events = static_cast<int16_t>(POLLIN), .revents = 0};
        ssize_t ret = TEMP_FAILURE_RETRY(::poll(&pfd, 1, 0));
        if (ret < 0) {
            int savedErrno = errno;
            if (savedErrno == EAGAIN || savedErrno == EWOULDBLOCK) {
                return WOULD_BLOCK;
            }

            LOG_RPC_DETAIL("RpcTransport poll(): %s", strerror(savedErrno));
            return -savedErrno;
        }

        if (pfd.revents & POLLNVAL) {
            return BAD_VALUE;
        }
        if (pfd.revents & POLLERR) {
            return DEAD_OBJECT;
        }
        if (pfd.revents & POLLHUP) {
            return DEAD_OBJECT;
        }
        if (pfd.revents & POLLIN) {
            return OK;
        }

        return WOULD_BLOCK;
    }

    template <typename SendOrReceive>
    status_t interruptableReadOrWrite(FdTrigger* fdTrigger, iovec* iovs, int niovs,
                                      SendOrReceive sendOrReceiveFun, const char* funName,
                                      int16_t event, const std::function<status_t()>& altPoll) {
        if (niovs < 0) {
            return BAD_VALUE;
        }

        // Since we didn't poll, we need to manually check to see if it was triggered. Otherwise, we
        // may never know we should be shutting down.
        if (fdTrigger->isTriggered()) {
            return DEAD_OBJECT;
        }

        bool havePolled = false;
        for (int i = 0; i < niovs; i++) {
            auto& iov = iovs[i];
            if (!iov.iov_len) {
                continue;
            }

            while (iov.iov_len) {
                ssize_t processSize = sendOrReceiveFun(mSocket.get(), &iov);
                if (processSize < 0) {
                    int savedErrno = errno;

                    // Still return the error on later passes, since it would expose
                    // a problem with polling
                    if (havePolled || (savedErrno != EAGAIN && savedErrno != EWOULDBLOCK)) {
                        LOG_RPC_DETAIL("RpcTransport %s(): %s", funName, strerror(savedErrno));
                        return -savedErrno;
                    }
                } else if (processSize == 0) {
                    return DEAD_OBJECT;
                } else {
                    LOG_ALWAYS_FATAL_IF(static_cast<size_t>(processSize) > iov.iov_len,
                                        "Too many bytes from %s(): %zd>%zu", funName, processSize,
                                        iov.iov_len);
                    iov.iov_base = reinterpret_cast<char*>(iov.iov_base) + processSize;
                    iov.iov_len -= processSize;
                    continue;
                }

                if (altPoll) {
                    if (status_t status = altPoll(); status != OK) return status;
                    if (fdTrigger->isTriggered()) {
                        return DEAD_OBJECT;
                    }
                } else {
                    if (status_t status = fdTrigger->triggerablePoll(mSocket.get(), event);
                        status != OK)
                        return status;
                    if (!havePolled) havePolled = true;
                }
            }
        }

        return OK;
    }

    status_t interruptableWriteFully(FdTrigger* fdTrigger, iovec* iovs, int niovs,
                                     const std::function<status_t()>& altPoll) override {
        auto writeFn = [](int fd, const iovec* iov) { return tipc_send(fd, iov, 1, nullptr, 0); };
        return interruptableReadOrWrite(fdTrigger, iovs, niovs, writeFn, "tipc_send", POLLOUT,
                                        altPoll);
    }

    status_t interruptableReadFully(FdTrigger* fdTrigger, iovec* iovs, int niovs,
                                    const std::function<status_t()>& altPoll) override {
        auto readFn = [](int fd, const iovec* iov) {
            return read(fd, iov->iov_base, iov->iov_len);
        };
        return interruptableReadOrWrite(fdTrigger, iovs, niovs, readFn, "read", POLLIN, altPoll);
    }

private:
    base::unique_fd mSocket;
};

// RpcTransportCtx for Trusty.
class RpcTransportCtxTrusty : public RpcTransportCtx {
public:
    std::unique_ptr<RpcTransport> newTransport(android::base::unique_fd fd,
                                               FdTrigger*) const override {
        return std::make_unique<RpcTransportTrusty>(std::move(fd));
    }
    std::vector<uint8_t> getCertificate(RpcCertificateFormat) const override { return {}; }
};

} // namespace

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryTrusty::newServerCtx() const {
    return std::make_unique<RpcTransportCtxTrusty>();
}

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryTrusty::newClientCtx() const {
    return std::make_unique<RpcTransportCtxTrusty>();
}

const char* RpcTransportCtxFactoryTrusty::toCString() const {
    return "trusty";
}

std::unique_ptr<RpcTransportCtxFactory> RpcTransportCtxFactoryTrusty::make() {
    return std::unique_ptr<RpcTransportCtxFactoryTrusty>(new RpcTransportCtxFactoryTrusty());
}

} // namespace android
