/*
 * Copyright (C) 2022 The Android Open Source Project
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
#include <binder/RpcTransport.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>

namespace android {

class Parcel;
class IRpcServer;
class RpcServer;
class RpcSocketAddress;
class RpcState;
class RpcTransport;
class FdTrigger;

constexpr uint32_t RPC_WIRE_PROTOCOL_VERSION_NEXT = 0;
constexpr uint32_t RPC_WIRE_PROTOCOL_VERSION_EXPERIMENTAL = 0xF0000000;
constexpr uint32_t RPC_WIRE_PROTOCOL_VERSION = RPC_WIRE_PROTOCOL_VERSION_EXPERIMENTAL;

/**
 * This represents a session (group of connections) between a client
 * and a server. Multiple connections are needed for multiple parallel "binder"
 * calls which may also have nested calls.
 */
class RpcSession final : public virtual RefBase {
public:
    // Create an RpcSession with default configuration (raw sockets).
    static sp<RpcSession> make();

    size_t getMaxIncomingThreads() {
        /* Only 1 thread on Trusty for now */
        return 1;
    }

    /**
     * Connects to an RPC server at the given port.
     */
    [[nodiscard]] status_t setupClient(const char* port);

    /**
     * Query the other side of the session for the root object hosted by that
     * process's RpcServer (if one exists)
     */
    sp<IBinder> getRootObject();

    /**
     * Query the other side of the session for the maximum number of threads
     * it supports (maximum number of concurrent non-nested synchronous transactions)
     */
    [[nodiscard]] status_t getRemoteMaxThreads(size_t* maxThreads);

    [[nodiscard]] bool shutdownAndWait(bool wait);

    [[nodiscard]] status_t transact(const sp<IBinder>& binder, uint32_t code, const Parcel& data,
                                    Parcel* reply, uint32_t flags);

    /**
     * Generally, you should not call this, unless you are testing error
     * conditions, as this is called automatically by BpBinders when they are
     * deleted (this is also why a raw pointer is used here)
     */
    [[nodiscard]] status_t sendDecStrong(const BpBinder* binder);

    ~RpcSession();

    /**
     * Server if this session is created as part of a server (symmetrical to
     * client servers). Otherwise, nullptr.
     */
    sp<RpcServer> server();

    // internal only
    const std::unique_ptr<RpcState>& state() { return mRpcBinderState; }

private:
    friend sp<RpcSession>;
    friend RpcServer;
    friend RpcState;
    explicit RpcSession(std::unique_ptr<RpcTransportCtx> ctx);

    // for 'target', see RpcState::sendDecStrongToTarget
    [[nodiscard]] status_t sendDecStrongToTarget(uint64_t address, size_t target);

    struct RpcConnection : public RefBase {
        std::unique_ptr<RpcTransport> rpcTransport;

        bool allowNested = false;
    };

    const std::unique_ptr<RpcTransportCtx> mCtx;

    // session-specific root object (if a different root is used for each
    // session)
    sp<IBinder> mSessionSpecificRootObject;

    std::vector<uint8_t> mId;

    std::unique_ptr<FdTrigger> mShutdownTrigger;

    std::unique_ptr<RpcState> mRpcBinderState;
};

} // namespace android
