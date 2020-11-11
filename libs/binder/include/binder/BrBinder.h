/*
 * Copyright (C) 2005 The Android Open Source Project
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

#include <binder/IBinder.h>
#include <binder/BpBinder.h> // FIXME: for ObjectManager (move it)
#include <binder/RpcConnection.h>
#include <utils/Mutex.h>

// ---------------------------------------------------------------------------
namespace android {

namespace internal {
class Stability;
};

class BrBinder : public IBinder
{
public:
    // FIXME: create from connection object, hide constructor BrBinder();
    BrBinder(const sp<RpcConnection>& connection, int address);

    const String16&     getInterfaceDescriptor() const override;
    bool                isBinderAlive() const override;
    status_t            pingBinder() override;
    status_t            dump(int fd, const Vector<String16>& args) override;

    status_t            transact(   uint32_t code,
                                    const Parcel& data,
                                    Parcel* reply,
                                    uint32_t flags) final override;

    status_t            linkToDeath(const sp<DeathRecipient>& recipient,
                                    void* cookie,
                                    uint32_t flags) override;

    status_t            unlinkToDeath(  const wp<DeathRecipient>& recipient,
                                        void* cookie,
                                        uint32_t flags,
                                        wp<DeathRecipient>* outRecipient) override;

    void                attachObject(   const void* objectID,
                                        void* object,
                                        void* cleanupCookie,
                                        object_cleanup_func func) final override;
    void*               findObject(const void* objectID) const final override;
    void                detachObject(const void* objectID) final override;

    // FIXME: integrate with BpBinder proxy counts

protected:
    virtual             ~BrBinder();

private:
    friend ::android::internal::Stability;
            int32_t             mStability;

            bool                isDescriptorCached() const;

    mutable Mutex               mLock;
            volatile int32_t    mAlive;
            BpBinder::ObjectManager       mObjects;
    mutable String16            mDescriptorCache;
            sp<RpcConnection>   mConnection;
            int mAddress;
};

} // namespace android

// ---------------------------------------------------------------------------
