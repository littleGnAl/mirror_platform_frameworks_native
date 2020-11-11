/*
 * Copyright (C) 2020 The Android Open Source Project
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
#include <binder/Parcel.h>
#include <binder/RpcConnection.h>

#include <map>

namespace android {

struct RpcWireHeader;

/**
 * Log a lot more information about RPC calls, when debugging issues. Usually,
 * you would want to enable this in only one process. If repeated issues require
 * a specific subset of logs to debug, this could be broken up like
 * IPCThreadState's.
 */
#define SHOULD_LOG_RPC_DETAIL false

#if SHOULD_LOG_RPC_DETAIL
#define LOG_RPC_DETAIL(...) ALOGI(__VA_ARGS__)
#else
#define LOG_RPC_DETAIL(...) ALOGV(__VA_ARGS__) // for type checking
#endif

/**
 * Abstracts away management of ref counts and the wire format from
 * RpcConnection
 */
class RpcState {
public:
    RpcState();
    ~RpcState();

    sp<IBinder> getRootObject(const base::unique_fd& fd,
                              const sp<RpcConnection>& connection);

    status_t transact(const base::unique_fd& fd,
                      const RpcAddress& address,
                      uint32_t code,
                      const Parcel& data,
                      const sp<RpcConnection>& connection,
                      Parcel* reply,
                      uint32_t flags);
    status_t sendDecStrong(const base::unique_fd& fd, const RpcAddress& address);
    status_t getAndExecuteCommand(const base::unique_fd& fd,
                                  const sp<RpcConnection>& connection);

    /**
     * Called by Parcel for outgoing binders. This implies one refcount of
     * ownership to the outgoing binder.
     */
    status_t onBinderLeaving(const sp<RpcConnection>& connection,
                             const sp<IBinder>& binder,
                             RpcAddress* outAddress);

    /**
     * Called by Parcel for incoming binders. This either returns the refcount
     * to the process, if this process already has one, or it takes ownership of
     * that refcount
     */
    sp<IBinder> onBinderEntering(const sp<RpcConnection>& connection, const RpcAddress& address);

    size_t countBinders();
    void dump();

private:
    status_t waitForReply(const base::unique_fd& fd,
                          const sp<RpcConnection>& connection,
                          Parcel* reply);
    status_t processServerCommand(const base::unique_fd& fd,
                                  const sp<RpcConnection>& connection,
                                  const RpcWireHeader& command);
    status_t processTransact(const base::unique_fd& fd,
                             const sp<RpcConnection>& connection,
                             const RpcWireHeader& command);
    status_t processDecStrong(const base::unique_fd& fd,
                           const RpcWireHeader& command);

    struct BinderNode {
        wp<IBinder> binder;
        // For a local binder:
        //     number of times we've sent this binder out of process,
        //     each time is one implicit strong ref.
        //     (see onBinderLeaving)
        // For a remote binder:
        //     this represents the number of references we are holding
        //     on this binder (see onBinderEntering)
        size_t strong;
    };

    std::mutex mNodeMutex;
    // binders known by both sides of a connection
    std::map<RpcAddress, BinderNode> mNodeForAddress;
};

} // namespace android
