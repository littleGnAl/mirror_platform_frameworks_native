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
#include "NdkBinder.h"

#include <android-base/logging.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>

using ::android::defaultServiceManager;
using ::android::IBinder;
using ::android::IPCThreadState;
using ::android::IServiceManager;
using ::android::LocalNdkBinder;
using ::android::sp;

AIBinder* AIBinder::newLocalBinder(const AIBinder_Class* clazz, AIBinder_Class_Impl impl) {
    LocalNdkBinder* localBinder = new LocalNdkBinder();
    AIBinder* ret = new AIBinder(clazz, impl, localBinder);
    localBinder->setAIBinder(ret);

    return ret;
}

AIBinder* AIBinder::newFromBinder(sp<IBinder> binder) {
    if (binder == nullptr) {
        return nullptr;
    }

    // FIXME: if something is served from this process but is not a local ndk binder (but rather is
    // a regular binder), then this is an invalid case. This case can't happen now, but it needs to
    // be handled for the future.
    LocalNdkBinder* localBinder = static_cast<LocalNdkBinder*>(binder->localBinder());
    if (localBinder != nullptr) {
        // FIXME: this AIBinder object must be shared (see comment in header)
        AIBinder* aibinder = localBinder->getAIBinder();
        return new AIBinder(aibinder->getClass(), aibinder->getImpl(), binder);
    }

    return new AIBinder(nullptr, nullptr, binder);
}

bool AIBinder::setClass(const AIBinder_Class* clazz) {
    using ::android::String8;

    CHECK(clazz != nullptr);

    if (mClazz == clazz) return true;

    String8 newDescriptor(clazz->getInterfaceDescriptor());

    if (mClazz != nullptr) {
        String8 currentDescriptor(mClazz->getInterfaceDescriptor());
        LOG(ERROR) << "Class cannot be set on object which already has a class. Trying to set to '"
                   << newDescriptor.c_str() << "' but already set to '" << currentDescriptor.c_str()
                   << "'.";
        return false;
    }

    String8 remoteDescriptor(clazz->getInterfaceDescriptor());

    if (clazz->getInterfaceDescriptor() != mBinder->getInterfaceDescriptor()) {
        LOG(ERROR) << "Expecting binder to have class '" << newDescriptor.c_str()
                   << "' but remote descriptor is actually '" << remoteDescriptor.c_str() << "'.";
        return false;
    }

    mClazz = clazz;
    return true;
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

AIBinder* AIBinder_new(const AIBinder_Class* clazz, void* args) {
    if (clazz == nullptr) {
        LOG(ERROR) << "Must provide class to construct local binder.";
        return nullptr;
    }

    AIBinder_Class_Impl impl = clazz->onCreate(args);
    return AIBinder::newLocalBinder(clazz, impl);
}

void AIBinder_delete(AIBinder* binder) {
    delete binder;
}

bool AIBinder_setClass(AIBinder* binder, const AIBinder_Class* clazz) {
    if (binder == nullptr || clazz == nullptr) {
        return false;
    }

    return binder->setClass(clazz);
}

const AIBinder_Class* AIBinder_getClass(AIBinder* binder) {
    if (binder == nullptr) {
        return nullptr;
    }

    return binder->getClass();
}

AIBinder_Class_Impl AIBinder_getImpl(AIBinder* binder) {
    if (binder == nullptr) {
        return nullptr;
    }

    return binder->getImpl();
}

binder_status_t AIBinder_prepareTransaction(const AIBinder* binder, AParcel** in) {
    if (binder == nullptr || in == nullptr) {
        LOG(ERROR) << "Prepare transaction requires non-null parameters.";
        return EX_NULL_POINTER;
    }
    if (!binder->isRemote()) {
        LOG(ERROR) << "Cannot execute transaction on a local binder.";
        return EX_ILLEGAL_STATE;
    }

    *in = new AParcel;

    binder_status_t status = ::android::initRemoteNdkBinderTransaction(binder, *in);
    if (status != EX_NONE) {
        delete *in;
        *in = nullptr;
    }

    return status;
}
binder_status_t AIBinder_transact(transaction_code_t code, const AIBinder* binder, AParcel* in,
                                  binder_flags_t flags, AParcel** out) {
    if (code < FIRST_CALL_TRANSACTION || code >= LAST_CALL_TRANSACTION) {
        LOG(ERROR) << "Only user-defined transactions can be made from the NDK.";
        return EX_UNSUPPORTED_OPERATION;
    }

    if (binder == nullptr || in == nullptr || out == nullptr) {
        LOG(ERROR) << "Transact requires non-null parameters.";
        return EX_NULL_POINTER;
    }

    *out = new AParcel;

    binder_status_t parcelStatus =
            binder->getBinder()->transact(code, *in->operator->(), (*out)->operator->(), flags);

    delete in;

    if (parcelStatus != EX_NONE) {
        delete *out;
        *out = nullptr;
    }

    return parcelStatus;
}

binder_status_t AIBinder_finalizeTransaction(const AIBinder* binder, AParcel* out) {
    (void)binder;

    // FIXME: can check that the transaction is finalized? parcel is empty?
    // FIXME add status to the parcel?

    delete out;

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
    sp<IBinder> binder = sm->getService(::android::String16(instance));

    return AIBinder::newFromBinder(binder);
}
