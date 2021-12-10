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
#include <log/log.h>

#include <poll.h>

#include <binder/RpcTransportTrusty.h>

#include "../FdTrigger.h"
#include "../RpcState.h"

using android::base::ErrnoError;
using android::base::Result;

namespace android {

namespace {

// RpcTransport for Trusty.
class RpcTransportTrusty : public RpcTransport {
public:
    explicit RpcTransportTrusty(android::base::unique_fd socket) : mSocket(std::move(socket)) {}
    Result<size_t> peek(void* buf, size_t size) override {
        // TODO
        return OK;
    }

    status_t interruptableWriteFully(FdTrigger* fdTrigger, iovec* iovs, int niovs,
                                     const std::function<status_t()>& altPoll) override {
        // TODO
        return OK;
    }

    status_t interruptableReadFully(FdTrigger* fdTrigger, iovec* iovs, int niovs,
                                    const std::function<status_t()>& altPoll) override {
        // TODO
        return OK;
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
