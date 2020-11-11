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
#include <binder/RpcAddress.h>
#include <utils/KeyedVector.h>
#include <utils/Mutex.h>
#include <utils/threads.h>

#include <unordered_map>

// ---------------------------------------------------------------------------
namespace android {

class RpcConnection;
namespace internal {
class Stability;
};

// FIXME: avoid explicit branching in this implementation
// - split into subclasses to differentiate socket proxy?
// - make IPCThreadState/socket stuff implement same interfaces?

using binder_proxy_limit_callback = void(*)(int);

class BpBinder : public IBinder
{
public:
    static BpBinder*    create(int32_t handle);
    static BpBinder*    create(const sp<RpcConnection>& connection, const RpcAddress* address);

    // FIXME: is bool the best type here for the future?
    bool                isRpcBinder() const;
    const RpcAddress*   address() const;
    sp<RpcConnection>   connection() const;
    // FIXME: hide or potentially change return type, since it won't always be
    // valid
    int32_t             handle() const;

    virtual const String16&    getInterfaceDescriptor() const;
    virtual bool        isBinderAlive() const;
    virtual status_t    pingBinder();
    virtual status_t    dump(int fd, const Vector<String16>& args);

    // NOLINTNEXTLINE(google-default-arguments)
    virtual status_t    transact(   uint32_t code,
                                    const Parcel& data,
                                    Parcel* reply,
                                    uint32_t flags = 0) final;

    // NOLINTNEXTLINE(google-default-arguments)
    virtual status_t    linkToDeath(const sp<DeathRecipient>& recipient,
                                    void* cookie = nullptr,
                                    uint32_t flags = 0);

    // NOLINTNEXTLINE(google-default-arguments)
    virtual status_t    unlinkToDeath(  const wp<DeathRecipient>& recipient,
                                        void* cookie = nullptr,
                                        uint32_t flags = 0,
                                        wp<DeathRecipient>* outRecipient = nullptr);

    virtual void        attachObject(   const void* objectID,
                                        void* object,
                                        void* cleanupCookie,
                                        object_cleanup_func func) final;
    virtual void*       findObject(const void* objectID) const final;
    virtual void        detachObject(const void* objectID) final;

    virtual BpBinder*   remoteBinder();

            void        sendObituary();

    static uint32_t     getBinderProxyCount(uint32_t uid);
    static void         getCountByUid(Vector<uint32_t>& uids, Vector<uint32_t>& counts);
    static void         enableCountByUid();
    static void         disableCountByUid();
    static void         setCountByUidEnabled(bool enable);
    static void         setLimitCallback(binder_proxy_limit_callback cb);
    static void         setBinderProxyCountWatermarks(int high, int low);

    class ObjectManager
    {
    public:
                    ObjectManager();
                    ~ObjectManager();

        void        attach( const void* objectID,
                            void* object,
                            void* cleanupCookie,
                            IBinder::object_cleanup_func func);
        void*       find(const void* objectID) const;
        void        detach(const void* objectID);

        void        kill();

    private:
                    ObjectManager(const ObjectManager&);
        ObjectManager& operator=(const ObjectManager&);

        struct entry_t
        {
            void* object;
            void* cleanupCookie;
            IBinder::object_cleanup_func func;
        };

        KeyedVector<const void*, entry_t> mObjects;
    };

protected:
    explicit            BpBinder(int32_t handle);
                        BpBinder(int32_t handle,int32_t trackedUid);
                        BpBinder(const sp<RpcConnection>& connection, const RpcAddress* address);

    virtual             ~BpBinder();
    virtual void        onFirstRef();
    virtual void        onLastStrongRef(const void* id);
    virtual bool        onIncStrongAttempted(uint32_t flags, const void* id);

private:
    // note commit 85180c00b24af8ef6cf1a801d69b4906b74271ab
    // offset(BpBinder, mHandle) was exposed as API until mid 2019
    //
    // FIXME: test if we can change this - only Parcel.cpp should have used it?
    const   int32_t             mHandle;

            bool                mIsSocket; // FIXME: garbage
            sp<RpcConnection>   mConnection; // if mIsSocket
    const   RpcAddress*         mAddress; // if mIsSocket

    friend ::android::internal::Stability;
            int32_t             mStability;

    struct Obituary {
        wp<DeathRecipient> recipient;
        void* cookie;
        uint32_t flags;
    };

            void                reportOneDeath(const Obituary& obit);
            bool                isDescriptorCached() const;

    mutable Mutex               mLock;
            volatile int32_t    mAlive;
            volatile int32_t    mObitsSent;
            Vector<Obituary>*   mObituaries;
            ObjectManager       mObjects;
    mutable String16            mDescriptorCache;
            int32_t             mTrackedUid;

    static Mutex                                sTrackingLock;
    static std::unordered_map<int32_t,uint32_t> sTrackingMap;
    static int                                  sNumTrackedUids;
    static std::atomic_bool                     sCountByUidEnabled;
    static binder_proxy_limit_callback          sLimitCallback;
    static uint32_t                             sBinderProxyCountHighWatermark;
    static uint32_t                             sBinderProxyCountLowWatermark;
    static bool                                 sBinderProxyThrottleCreate;
};

} // namespace android

// ---------------------------------------------------------------------------
