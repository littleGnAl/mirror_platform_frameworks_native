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

#define LOG_TAG "BrBinder"

#include <binder/BrBinder.h>

#include <binder/IPCThreadState.h>
#include <binder/Stability.h>
#include <cutils/compiler.h>
#include <utils/Log.h>

#include <stdio.h>

namespace android {

BrBinder::BrBinder(const sp<RpcConnection>& connection, int address)
    : mStability(0)
    , mAlive(1)
    , mConnection(connection)
    , mAddress(address)
{
    // FIXME: lifetimes
    extendObjectLifetime(OBJECT_LIFETIME_WEAK);
}

bool BrBinder::isDescriptorCached() const {
    Mutex::Autolock _l(mLock);
    return mDescriptorCache.size() ? true : false;
}

const String16& BrBinder::getInterfaceDescriptor() const
{
    // FIXME: de-dupe transaction logic with BpBinder.
    if (isDescriptorCached() == false) {
        Parcel send, reply;
        // do the IPC without a lock held.
        status_t err = const_cast<BrBinder*>(this)->transact(
                INTERFACE_TRANSACTION, send, &reply, 0);
        if (err == NO_ERROR) {
            String16 res(reply.readString16());
            Mutex::Autolock _l(mLock);
            // mDescriptorCache could have been assigned while the lock was
            // released.
            if (mDescriptorCache.size() == 0)
                mDescriptorCache = res;
        }
    }

    // we're returning a reference to a non-static object here. Usually this
    // is not something smart to do, however, with binder objects it is
    // (usually) safe because they are reference-counted.

    return mDescriptorCache;
}

bool BrBinder::isBinderAlive() const
{
    return mAlive != 0;
}

status_t BrBinder::pingBinder()
{
    // FIXME: de-dupe parceling logic
    Parcel send;
    Parcel reply;
    return transact(PING_TRANSACTION, send, &reply, 0);
}

status_t BrBinder::dump(int fd, const Vector<String16>& args)
{
    // FIXME: de-dupe parceling logic
    Parcel send;
    Parcel reply;
    send.writeFileDescriptor(fd);
    const size_t numArgs = args.size();
    send.writeInt32(numArgs);
    for (size_t i = 0; i < numArgs; i++) {
        send.writeString16(args[i]);
    }
    status_t err = transact(DUMP_TRANSACTION, send, &reply, 0);
    return err;
}

status_t BrBinder::transact(
    uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags)
{
    // Once a binder has died, it will never come back to life.
    if (mAlive) {
        // FIXME: de-dupe stability logic
        bool privateVendor = flags & FLAG_PRIVATE_VENDOR;
        // don't send userspace flags to the kernel
        flags = flags & ~FLAG_PRIVATE_VENDOR;

        // user transactions require a given stability level
        if (code >= FIRST_CALL_TRANSACTION && code <= LAST_CALL_TRANSACTION) {
            using android::internal::Stability;

            auto stability = Stability::get(this);
            auto required = privateVendor ? Stability::VENDOR : Stability::getLocalStability();

            if (CC_UNLIKELY(!Stability::check(stability, required))) {
                ALOGE("Cannot do a user transaction on a %s binder in a %s context.",
                    Stability::stabilityString(stability).c_str(),
                    Stability::stabilityString(required).c_str());
                return BAD_TYPE;
            }
        }

        status_t status = mConnection->transact(mAddress, code, data, reply, flags);
        if (status == DEAD_OBJECT) mAlive = 0;
        return status;
    }

    return DEAD_OBJECT;
}

status_t BrBinder::linkToDeath(
    const sp<DeathRecipient>& recipient, void* cookie, uint32_t flags)
{
    // FIXME: handle
    (void) recipient;
    (void) cookie;
    (void) flags;
    return UNKNOWN_ERROR;
}

// NOLINTNEXTLINE(google-default-arguments)
status_t BrBinder::unlinkToDeath(
    const wp<DeathRecipient>& recipient, void* cookie, uint32_t flags,
    wp<DeathRecipient>* outRecipient)
{
    // FIXME: handle
    (void) recipient;
    (void) cookie;
    (void) flags;
    (void) outRecipient;
    return UNKNOWN_ERROR;
}

void BrBinder::attachObject(
    const void* objectID, void* object, void* cleanupCookie,
    object_cleanup_func func)
{
    AutoMutex _l(mLock);
    mObjects.attach(objectID, object, cleanupCookie, func);
}

void* BrBinder::findObject(const void* objectID) const
{
    AutoMutex _l(mLock);
    return mObjects.find(objectID);
}

void BrBinder::detachObject(const void* objectID)
{
    AutoMutex _l(mLock);
    mObjects.detach(objectID);
}

BrBinder::~BrBinder()
{
}

} // namespace android
