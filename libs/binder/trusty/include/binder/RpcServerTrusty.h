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
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>
#include <binder/RpcTransport.h>
#include <utils/Errors.h>
#include <utils/RefBase.h>

#include <map>
#include <vector>

#include <lib/tipc/tipc_srv.h>

namespace android {

/**
 * This is the Trusty-specific RPC server code.
 */
class RpcServerTrusty : public virtual RefBase, public RpcServer {
public:
    static sp<RpcServerTrusty> make(
            std::unique_ptr<RpcTransportCtxFactory> rpcTransportCtxFactory = nullptr);

    [[nodiscard]] status_t setupTrustyServer(tipc_hset* hset, const char* port,
                                             const tipc_port_acl* acl, size_t msg_max_size);

private:
    friend sp<RpcServerTrusty>;
    explicit RpcServerTrusty(std::shared_ptr<RpcTransportCtx> ctx) : RpcServer(std::move(ctx)) {}

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

    tipc_port mTipcPort;
};

} // namespace android
