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

// FIXME: docs, justify global
// FIXME: make a lot of these functions private
// FIXME: document what this replyConnection thing is
class RpcState {
public:
    // FIXME: combine with process state or build similarly?
    static RpcState& self();

    sp<IBinder> getRootObject(const base::unique_fd& fd,
                              const sp<RpcConnection>& replyConnection);

    status_t transact(const base::unique_fd& fd,
                      const RpcAddress& address,
                      uint32_t code,
                      const Parcel& data,
                      const sp<RpcConnection>& replyConnection,
                      Parcel* reply,
                      uint32_t flags);
    status_t waitForReply(const base::unique_fd& fd,
                          const sp<RpcConnection>& connection,
                          Parcel* reply);
    status_t sendDecStrong(const base::unique_fd& fd, const RpcAddress& address);
    status_t getAndExecuteCommand(const base::unique_fd& fd,
                                  const sp<RpcConnection>& replyConnection);

    /**
     * This object can be retrieved by whoever can make a connection this
     * process without any restrictions. Whatever this object is, it should
     * implement some restrictions/security model.
     */
    void setRootObject(const sp<IBinder>& binder);

    /**
     * Called by Parcel for outgoing binders. This implies one refcount of
     * ownersip to the outgoing binder.
     */
    const RpcAddress& onBinderLeaving(const sp<IBinder>& binder);

    /**
     * Called by Parcel for incoming binders. This either returns the refcount
     * to the process, if this process already has one, or it takes ownership of
     * that refcount
     */
    sp<IBinder> onBinderEntering(const sp<RpcConnection>& connection, const RpcAddress& address);

    size_t countBinders();
    void dump();

private:
    // FIXME: needing this function is a product of how we read packets
    status_t processServerCommand(const base::unique_fd& fd,
                                  const sp<RpcConnection>& replyConnection,
                                  const RpcWireHeader& command);
    status_t processTransact(const base::unique_fd& fd,
                             const sp<RpcConnection>& replyConnection,
                             const RpcWireHeader& command);
    status_t processDecRef(const base::unique_fd& fd,
                           const RpcWireHeader& command);

    // FIXME: some of this state should be associated per-IPC-server

    // This object should only be in mNodeForAddress when it is sent to another
    // process. Otherwise, it is only held here.
    sp<IBinder> mRootObject;

    struct BinderNode {
        wp<IBinder> binder;
        // number of times we've sent this binder out of process
        // (each time is one implicit strong ref)
        size_t strong;
    };
    // binders known by both sides of a connection
    // FIXME: synchronization
    // FIXME: unordered hash?
    // FIXME: clean this up when binders are deleted
    // FIXME: should separate local vs remote !!!!
    std::map<RpcAddress, BinderNode> mNodeForAddress;
};

} // namespace android
