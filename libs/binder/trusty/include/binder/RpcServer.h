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

    // TODO: acl too
    [[nodiscard]] status_t setupTrustyServer(const char* port);

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
    void setPerSessionRootObject(std::function<sp<IBinder>(const sockaddr*, socklen_t)>&& object);
    sp<IBinder> getRootObject();

    [[nodiscard]] bool shutdown();

    ~RpcServer();

private:
    friend sp<RpcServer>;
    explicit RpcServer(std::unique_ptr<RpcTransportCtx> ctx);

    const std::unique_ptr<RpcTransportCtx> mCtx;
    base::unique_fd mServer; // socket we are accepting sessions on

    sp<IBinder> mRootObject;
    wp<IBinder> mRootObjectWeak;
    std::function<sp<IBinder>(const sockaddr*, socklen_t)> mRootObjectFactory;
};

} // namespace android
