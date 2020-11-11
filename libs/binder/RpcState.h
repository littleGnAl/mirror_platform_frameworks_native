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
class RpcState {
public:
    // FIXME: combine with process state or build similarly?
    static RpcState& self();

    // FIXME: do we need separate connection/fd args - need tests with
    // multi-threading/multiple connections to see
    // FIXME: should connection arg be the actual reply connection, so we let
    // RpcConnection construct it?
    status_t transact(const sp<RpcConnection>& connection,
                      const base::unique_fd& fd,
                      const RpcWireAddress* address,
                      uint32_t code,
                      const Parcel& data,
                      Parcel* reply,
                      uint32_t flags);
    status_t waitForReply(const sp<RpcConnection>& connection,
                          const base::unique_fd& fd,
                          Parcel* reply);
    status_t sendDecStrong(const base::unique_fd& fd, const RpcWireAddress* address);
    status_t getAndExecuteCommand(const base::unique_fd& fd);

    /**
     * FIXME: perhaps allow specifying an address/capability here so that
     * whoever registers the root object can set the address, limiting who can
     * see it?
     */
    void setRootObject(const sp<IBinder>& binder);

    // FIXME: switch binder to be wp here, since we keep wp
    // FIXME: document address lifetime, or switch address to be
    // owned by the binder
    /**
     * Should be called on out-going binders. This comes with an explicit incRef
     * of ownership, which is associated with sending a binder.
     */
    const RpcWireAddress* attachBinder(const sp<IBinder>& binder);
    sp<IBinder> lookupOrCreateProxy(const sp<RpcConnection>& connection, RpcWireAddress&& address);

    // FIXME: this needs to be better
    // debugging dump of rpc state contents
    void dump();

private:
    // FIXME: needing this function is a product of how we read packets
    status_t processServerCommand(const base::unique_fd& fd,
                                  const RpcWireHeader& command);
    status_t processTransact(const base::unique_fd& fd, const RpcWireHeader& command);
    status_t processDecRef(const base::unique_fd& fd, const RpcWireHeader& command);

    // binders known by both sides of a connection
    // FIXME: synchronization
    // FIXME: avoid sp
    // FIXME: do not make copies of RpcWireAddress, since they will be large
    //     maybe it's best to keep here, so that sizeof(BpBinder) isn't too
    //     big
    // FIXME: unordered hash
    // FIXME: clean this up when binders are deleted
    std::map<RpcWireAddress, wp<IBinder>> mBinderForAddress;

    // FIXME: could be more efficient w/ incStrong/decStrong we hold ourselves?
    // - at least, should be combined in above data structure/have faster
    // lookups
    // FIXME: should this be associated with a server instead, so that when
    // there is an error, we can drop everything associated with that server?
    std::vector<sp<IBinder>> mExternalStrongRefs;
};

} // namespace android
