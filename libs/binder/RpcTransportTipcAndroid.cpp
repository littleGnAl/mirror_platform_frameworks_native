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
#include <binder/RpcTransportTipcAndroid.h>
#include <log/log.h>
#include <poll.h>
#include <trusty/tipc.h>

#include "FdTrigger.h"
#include "RpcState.h"
#include "RpcTransportUtils.h"

using android::base::Error;
using android::base::Result;

namespace android {

namespace {

// RpcTransport for Trusty.
class RpcTransportTipcAndroid : public RpcTransport {
public:
    explicit RpcTransportTipcAndroid(android::base::unique_fd socket)
          : mSocket(std::move(socket)) {}

    status_t pollRead() override {
        if (mReadBufferPos < mReadBuffer.size()) {
            // We have more data in the read buffer
            return OK;
        }

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

    status_t interruptableWriteFully(
            FdTrigger* fdTrigger, iovec* iovs, int niovs,
            const std::optional<android::base::function_ref<status_t()>>& altPoll,
            const std::vector<std::variant<base::unique_fd, base::borrowed_fd>>* /*ancillaryFds*/)
            override {
        auto writeFn = [&](iovec* iovs, size_t niovs) -> ssize_t {
            if (niovs == 0) {
                return 0;
            }
            // TODO: send ancillaryFds
            return TEMP_FAILURE_RETRY(tipc_send(mSocket.get(), iovs, niovs, nullptr, 0));
        };
        return interruptableReadOrWrite(mSocket.get(), fdTrigger, iovs, niovs, writeFn, "tipc_send",
                                        POLLOUT, altPoll);
    }

    status_t interruptableReadFully(
            FdTrigger* fdTrigger, iovec* iovs, int niovs,
            const std::optional<android::base::function_ref<status_t()>>& altPoll,
            std::vector<std::variant<base::unique_fd, base::borrowed_fd>>* /*ancillaryFds*/)
            override {
        auto readFn = [&](iovec* iovs, size_t niovs) -> ssize_t {
            if (niovs == 0) {
                return 0;
            }

            status_t ret = fillReadBuffer();
            if (ret != OK) {
                return ret;
            }

            ssize_t processSize = 0;
            for (size_t i = 0; i < niovs; i++) {
                auto& iov = iovs[i];
                LOG_ALWAYS_FATAL_IF(iov.iov_len > mReadBuffer.size() - mReadBufferPos,
                                    "Iov %zu crosses message boundary", i);

                memcpy(iov.iov_base, mReadBuffer.data() + mReadBufferPos, iov.iov_len);
                mReadBufferPos += iov.iov_len;
                processSize += iov.iov_len;
            }

            return processSize;
        };
        return interruptableReadOrWrite(mSocket.get(), fdTrigger, iovs, niovs, readFn, "read",
                                        POLLIN, altPoll);
    }

private:
    status_t fillReadBuffer() {
        if (mReadBufferPos < mReadBuffer.size()) {
            return OK;
        }

        while (true) {
            if (mReadBuffer.empty()) {
                mReadBuffer.resize(kDefaultBufferSize);
            }

            ssize_t processSize =
                    TEMP_FAILURE_RETRY(read(mSocket.get(), mReadBuffer.data(), mReadBuffer.size()));
            if (processSize == 0) {
                return DEAD_OBJECT;
            } else if (processSize < 0) {
                int savedErrno = errno;
                if (savedErrno == EMSGSIZE) {
                    // Buffer was too small, double it and retry
                    mReadBuffer.resize(mReadBuffer.size() * 2);
                    continue;
                } else {
                    LOG_RPC_DETAIL("RpcTransport fillBuffer(): %s", strerror(savedErrno));
                    return -savedErrno;
                }
            } else {
                mReadBuffer.resize(processSize);
                mReadBufferPos = 0;
                return OK;
            }
        }
    }

    base::unique_fd mSocket;

    // For now, we copy all the input data into a temporary buffer because
    // we might get multiple interruptableReadFully calls per message, but
    // the tipc device only allows one read call. We read every message into
    // this temporary buffer, then return pieces of it from our method.
    static constexpr size_t kDefaultBufferSize = 16;
    std::vector<uint8_t> mReadBuffer;
    size_t mReadBufferPos = 0;
};

// RpcTransportCtx for Trusty.
class RpcTransportCtxTipcAndroid : public RpcTransportCtx {
public:
    std::unique_ptr<RpcTransport> newTransport(android::base::unique_fd fd,
                                               FdTrigger*) const override {
        return std::make_unique<RpcTransportTipcAndroid>(std::move(fd));
    }
    std::vector<uint8_t> getCertificate(RpcCertificateFormat) const override { return {}; }
};

} // namespace

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryTipcAndroid::newServerCtx() const {
    return std::make_unique<RpcTransportCtxTipcAndroid>();
}

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryTipcAndroid::newClientCtx() const {
    return std::make_unique<RpcTransportCtxTipcAndroid>();
}

const char* RpcTransportCtxFactoryTipcAndroid::toCString() const {
    return "trusty";
}

std::unique_ptr<RpcTransportCtxFactory> RpcTransportCtxFactoryTipcAndroid::make() {
    return std::unique_ptr<RpcTransportCtxFactoryTipcAndroid>(
            new RpcTransportCtxFactoryTipcAndroid());
}

} // namespace android
