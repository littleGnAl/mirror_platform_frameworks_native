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

#include <trusty_ipc.h>
#include <uapi/err.h>

#include <binder/RpcSession.h>
#include <binder/RpcTransportRaw.h>
#include <log/log.h>

#include "../FdTrigger.h"
#include "../RpcState.h"

using android::base::Error;
using android::base::Result;

namespace android {

namespace {

static status_t statusFromTrusty(int rc) {
    LOG_RPC_DETAIL("Trusty error: %d", rc);
    switch (rc) {
        case NO_ERROR:
            return OK;
        /* TODO: more errors */
        default:
            return UNKNOWN_ERROR;
    }
}

// RpcTransport for Trusty.
class RpcTransportRaw : public RpcTransport {
public:
    explicit RpcTransportRaw(android::base::unique_fd socket) : mSocket(std::move(socket)) {}
    ~RpcTransportRaw() {
        if (mHaveMessage) {
            put_msg(mSocket.get(), mMessageInfo.id);
        }
    }

    status_t pollRead() override {
        auto status = ensureMessage(false);
        if (status != OK) {
            return status;
        }
        return mHaveMessage ? OK : WOULD_BLOCK;
    }

    status_t interruptableWriteFully(FdTrigger* fdTrigger, iovec* iovs, int niovs,
                                     const std::function<status_t()>& altPoll) override {
        if (niovs < 0) {
            return BAD_VALUE;
        }

        for (int i = 0; i < niovs; i++) {
            auto& iov = iovs[i];
            if (!iov.iov_len) {
                continue;
            }

            ipc_msg_t msg{
                    .num_iov = 1,
                    .iov = &iov,
                    .num_handles = 0,
                    .handles = nullptr,
            };
            int rc = send_msg(mSocket.get(), &msg);
            if (rc < 0) {
                return statusFromTrusty(rc);
            }
            LOG_ALWAYS_FATAL_IF(static_cast<size_t>(rc) != iov.iov_len,
                                "Sent the wrong number of bytes %d!=%zu", rc, iov.iov_len);
        }

        return OK;
    }

    status_t interruptableReadFully(FdTrigger* fdTrigger, iovec* iovs, int niovs,
                                    const std::function<status_t()>& altPoll) override {
        if (niovs < 0) {
            return BAD_VALUE;
        }

        for (int i = 0; i < niovs; i++) {
            auto& iov = iovs[i];
            while (iov.iov_len) {
                auto status = ensureMessage(true);
                if (status != OK) {
                    return status;
                }
                LOG_ALWAYS_FATAL_IF(mMessageInfo.len > iov.iov_len,
                                    "Received too many bytes %zu>%zu", mMessageInfo.len,
                                    iov.iov_len);

                ipc_msg_t msg{
                        .num_iov = 1,
                        .iov = &iov,
                        .num_handles = 0,
                        .handles = nullptr,
                };
                int rc = read_msg(mSocket.get(), mMessageInfo.id, 0, &msg);
                if (rc < 0) {
                    return statusFromTrusty(rc);
                }
                put_msg(mSocket.get(), mMessageInfo.id);
                mHaveMessage = false;

                auto processSize = static_cast<size_t>(rc);
                LOG_ALWAYS_FATAL_IF(processSize != mMessageInfo.len,
                                    "Read the wrong number of bytes %zu!=%zu", processSize,
                                    mMessageInfo.len);
                iov.iov_base = reinterpret_cast<char*>(iov.iov_base) + processSize;
                iov.iov_len -= processSize;
            }
        }

        return OK;
    }

private:
    status_t ensureMessage(bool wait) {
        int rc;
        if (mHaveMessage) {
            return OK;
        }

        /* TODO: interruptible wait, maybe with a timeout??? */
        uevent uevt;
        rc = ::wait(mSocket.get(), &uevt, wait ? INFINITE_TIME : 0);
        if (rc < 0) {
            if (rc == ERR_TIMED_OUT && !wait) {
                // If we timed out with wait==false, then there's no message
                return OK;
            }
            return statusFromTrusty(rc);
        }
        if (!(uevt.event & IPC_HANDLE_POLL_MSG)) {
            /* No message, terminate here and leave mHaveMessage false */
            return OK;
        }

        rc = get_msg(mSocket.get(), &mMessageInfo);
        if (rc < 0) {
            return statusFromTrusty(rc);
        }

        mHaveMessage = true;
        return OK;
    }

    base::unique_fd mSocket;

    bool mHaveMessage = false;
    ipc_msg_info mMessageInfo;
};

// RpcTransportCtx for Trusty.
class RpcTransportCtxRaw : public RpcTransportCtx {
public:
    std::unique_ptr<RpcTransport> newTransport(android::base::unique_fd fd,
                                               FdTrigger*) const override {
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

const char* RpcTransportCtxFactoryRaw::toCString() const {
    return "trusty";
}

std::unique_ptr<RpcTransportCtxFactory> RpcTransportCtxFactoryRaw::make() {
    return std::unique_ptr<RpcTransportCtxFactoryRaw>(new RpcTransportCtxFactoryRaw());
}

} // namespace android
