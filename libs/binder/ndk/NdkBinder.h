/*
 * Copyright (C) 2018 The Android Open Source Project
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

// These are adapters from libbinder binder objects to the representation in libbinder_ndk. They
// also implement the protocol differences which are to be considered implementation details of
// libbinder and are not exposed to the NDK.

#include <binder/AIBinder.h>
#include <binder/Binder.h>
#include <binder/BpBinder.h>

namespace android {

class LocalNdkBinder : public BBinder {
public:
    void setAIBinder(AIBinder* binder);
    const String16& getInterfaceDescriptor() const override;
    binder_status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply,
                               uint32_t flags) override;

private:
    AIBinder* mBinder;
};

// FIXME: delete these (not actually needed)

class BppBinder : public BpRefBase, public IBinder {
public:
    BppBinder(const sp<IBinder>& remote) : BpRefBase(remote) {}
    const String16& getInterfaceDescriptor() const override {
        return remote()->getInterfaceDescriptor();
    }
    bool isBinderAlive() const override { return remote()->isBinderAlive(); }
    status_t pingBinder() override { return remote()->pingBinder(); }
    status_t dump(int fd, const Vector<String16>& args) override {
        return remote()->dump(fd, args);
    }
    status_t transact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) override {
        return remote()->transact(code, data, reply, flags);
    }
    status_t linkToDeath(const sp<DeathRecipient>& recipient, void* cookie,
                         uint32_t flags) override {
        return remote()->linkToDeath(recipient, cookie, flags);
    }
    status_t unlinkToDeath(const wp<DeathRecipient>& recipient, void* cookie, uint32_t flags,
                           wp<DeathRecipient>* outRecipient) override {
        return remote()->unlinkToDeath(recipient, cookie, flags, outRecipient);
    }
    void attachObject(const void* objectID, void* object, void* cleanupCookie,
                      object_cleanup_func func) override {
        return remote()->attachObject(objectID, object, cleanupCookie, func);
    }
    void* findObject(const void* objectID) const override { return remote()->findObject(objectID); }
    void detachObject(const void* objectID) override { return remote()->detachObject(objectID); }
};

class RemoteNdkBinder : public BppBinder {
public:
    RemoteNdkBinder(const sp<IBinder>& remote);

    status_t transact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags);
};

} // namespace android
