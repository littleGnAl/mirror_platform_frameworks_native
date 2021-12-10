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
#include <binder/RpcSession.h>
#include <binder/RpcTransport.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>

#include <map>
#include <vector>

#include <lib/tipc/tipc_srv.h>

namespace android {

class FdTrigger;
class RpcSocketAddress;

/**
 * This is the base interface common to all concrete RPC server implementations.
 */
class RpcServer : public virtual RefBase {
public:
    static sp<RpcServer> make(
            std::unique_ptr<RpcTransportCtxFactory> rpcTransportCtxFactory = nullptr);

    [[nodiscard]] status_t setupTrustyServer(tipc_hset* hset, const char* port,
                                             const tipc_port_acl* acl, size_t msg_max_size);

    /**
     * If setup*Server has been successful, return true. Otherwise return false.
     */
    [[nodiscard]] bool hasServer();

    /**
     * If hasServer(), return the server FD. Otherwise return invalid FD.
     */
    [[nodiscard]] base::unique_fd releaseServer();

    /**
     * By default, the latest protocol version which is supported by a client is
     * used. However, this can be used in order to prevent newer protocol
     * versions from ever being used. This is expected to be useful for testing.
     */
    void setProtocolVersion(uint32_t version);

    /**
     * The root object can be retrieved by any client, without any
     * authentication. TODO(b/183988761)
     *
     * Holds a strong reference to the root object.
     */
    void setRootObject(const sp<IBinder>& binder);
    /**
     * Holds a weak reference to the root object.
     */
    void setRootObjectWeak(const wp<IBinder>& binder);
    /**
     * Allows a root object to be created for each session
     */
    void setPerSessionRootObject(std::function<sp<IBinder>(const uuid*)>&& object);
    sp<IBinder> getRootObject();

    [[nodiscard]] bool shutdown();

    ~RpcServer();

private:
    friend sp<RpcServer>;
    explicit RpcServer(std::unique_ptr<RpcTransportCtx> ctx);

    static int handleConnect(const tipc_port* port, handle_t chan, const uuid* peer, void** ctx_p);
    static int handleMessage(const tipc_port* port, handle_t chan, void* ctx);
    static void handleDisconnect(const tipc_port* port, handle_t chan, void* ctx);
    static void handleChannelCleanup(void* ctx);

    static constexpr tipc_srv_ops kTipcOps = {
            .on_connect = &handleConnect,
            .on_message = &handleMessage,
            .on_disconnect = &handleDisconnect,
            .on_channel_cleanup = &handleChannelCleanup,
    };

    const std::unique_ptr<RpcTransportCtx> mCtx;
    std::optional<uint32_t> mProtocolVersion;
    base::unique_fd mServer; // socket we are accepting sessions on

    tipc_port mTipcPort;

    sp<IBinder> mRootObject;
    wp<IBinder> mRootObjectWeak;
    std::function<sp<IBinder>(const uuid*)> mRootObjectFactory;
    std::map<std::vector<uint8_t>, sp<RpcSession>> mSessions;
    std::unique_ptr<FdTrigger> mShutdownTrigger;
};

} // namespace android
