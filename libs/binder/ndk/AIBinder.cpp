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
using ::android::IPCThreadState;
using ::android::IServiceManager;
using ::android::sp;

// FIXME: override BBinder to have interface descriptors work
// class LocalNdkBinder : public BBinder {
//     LocalNdkBinder(const AIBinder_Class* clazz) : mClazz(clazz) {}

//     const ::android::String16& getInterfaceDescriptor() const override;
// private:
//     const AIBinder_Class* mClazz;
// };

AIBinder* AIBinder::newLocalBinder(const AIBinder_Class* clazz, AIBinder_Class_Impl impl) {
    return new AIBinder(clazz, impl, new BBinder());
}
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

AStatus* AIBinder_transact(transaction_code_t code, AIBinder* binder, binder_flags_t flags,
                           AParcel* in, AParcel* out) {
    if (binder == nullptr || in == nullptr || out == nullptr) {
        return AStatus_newTransportSpecific(EX_NULL_POINTER);
    }

    (void)flags;

    service_status_t parcelStatus =
            binder->getBinder()->transact(code, *in->operator->(), out->operator->(), flags);

    if (parcelStatus != EX_NONE) {
        return AStatus_newServiceSpecific(parcelStatus);
    }

    return AStatus_newOk();
}

AStatus* AIBinder_register(AIBinder* binder, const char* instance) {
    if (binder == nullptr || instance == nullptr) {
        return AStatus_newTransportSpecific(EX_NULL_POINTER);
    }

    sp<IServiceManager> sm = defaultServiceManager();
    sm->addService(::android::String16(instance), binder->getBinder());

    return AStatus_newOk();
}
AIBinder_Class_Impl AIBinder_getImpl(AIBinder* binder) {
    if (binder == nullptr) {
        return nullptr;
    }

    return binder->getImpl();
}
