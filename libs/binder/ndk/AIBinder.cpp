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

#include <binder/AIBinder.h>
#include "AIBinder_internal.h"

#include <binder/AStatus.h>
#include "AParcel_internal.h"

#include <binder/Binder.h>
#include <binder/BpBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>

using ::android::BBinder;
using ::android::defaultServiceManager;
using ::android::IBinder;
using ::android::IPCThreadState;
using ::android::IServiceManager;
using ::android::Parcel;
using ::android::sp;

class LocalNdkBinder : public BBinder {
public:
    void setAIBinder(AIBinder* binder) { mBinder = binder; }

    const ::android::String16& getInterfaceDescriptor() const override {
        return mBinder->getClass()->getInterfaceDescriptor();
    }

    binder_status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) {
        // FIXME: doing it this way too weird? I think it makes more sense
        if (code >= FIRST_CALL_TRANSACTION && code < LAST_CALL_TRANSACTION) {
            // FIXME: allow read-only parcel to read only
            // FIXME: check interface token
            // FIXME: write status
            AParcel in = AParcel(const_cast<Parcel*>(&data), false /*owns*/);
            AParcel out = AParcel(reply, false /*owns*/);
            return mBinder->getClass()->onTransact(code, mBinder, &in, &out);
        } else {
            return BBinder::onTransact(code, data, reply, flags);
        }
    }

private:
    AIBinder* mBinder;
};

AIBinder* AIBinder::newLocalBinder(const AIBinder_Class* clazz, AIBinder_Class_Impl impl) {
    LocalNdkBinder* localBinder = new LocalNdkBinder();
    AIBinder* ret = new AIBinder(clazz, impl, localBinder);
    localBinder->setAIBinder(ret);

    return ret;
}

// FIXME: wrap RemoteBinder for writing interface token and returning error code

AIBinder* AIBinder::newRemoteBinder(::android::sp<::android::IBinder> remoteBinder) {
    return new AIBinder(nullptr, nullptr, remoteBinder);
}

AIBinder_Class::AIBinder_Class(const char* interfaceDescriptor, AIBinder_Class_onCreate onCreate,
                               AIBinder_Class_onDestroy onDestroy,
                               AIBinder_Class_onTransact onTransact)
      : onCreate(onCreate),
        onDestroy(onDestroy),
        onTransact(onTransact),
        mInterfaceDescriptor(interfaceDescriptor) {}

AIBinder_Class* AIBinder_Class_define(const char* interfaceDescriptor,
                                      AIBinder_Class_onCreate onCreate,
                                      AIBinder_Class_onDestroy onDestroy,
                                      AIBinder_Class_onTransact onTransact) {
    if (interfaceDescriptor == nullptr || onCreate == nullptr || onDestroy == nullptr ||
        onTransact == nullptr) {
        return nullptr;
    }

    return new AIBinder_Class(interfaceDescriptor, onCreate, onDestroy, onTransact);
}

// FIXME: new from remote

AIBinder* AIBinder_new(const AIBinder_Class* clazz, void* args) {
    if (clazz == nullptr) {
        return nullptr;
    }

    AIBinder_Class_Impl impl = clazz->onCreate(args);
    return AIBinder::newLocalBinder(clazz, impl);
}

binder_status_t AIBinder_transact(transaction_code_t code, AIBinder* binder, AParcel* in,
                                  AParcel* out, binder_flags_t flags) {
    if (binder == nullptr || in == nullptr || out == nullptr) {
        return EX_NULL_POINTER;
    }

    (void)flags;

    binder_status_t parcelStatus =
            binder->getBinder()->transact(code, *in->operator->(), out->operator->(), flags);

    if (parcelStatus != EX_NONE) {
        return parcelStatus;
    }

    return EX_NONE;
}

binder_status_t AIBinder_register(AIBinder* binder, const char* instance) {
    if (binder == nullptr || instance == nullptr) {
        return EX_NULL_POINTER;
    }

    sp<IServiceManager> sm = defaultServiceManager();
    sm->addService(::android::String16(instance), binder->getBinder());

    return EX_NONE;
}
AIBinder* AIBinder_get(const char* instance) {
    if (instance == nullptr) {
        return nullptr;
    }

    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> remoteBinder = sm->getService(::android::String16(instance));

    if (remoteBinder == nullptr) {
        return nullptr;
    }

    return AIBinder::newRemoteBinder(remoteBinder);
}
AIBinder_Class_Impl AIBinder_getImpl(AIBinder* binder) {
    if (binder == nullptr) {
        return nullptr;
    }

    return binder->getImpl();
}
