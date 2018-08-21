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

AIBinder::AIBinder(const AIBinder_Class* clazz, void* userData,
                   ::android::sp<::android::IBinder> binder)
      : mClazz(clazz), mUserData(userData), mBinder(binder) {
    CHECK(mBinder != nullptr);
}

AIBinder::~AIBinder() {
    if (mClazz != nullptr) {
        mClazz->onDestroy(mUserData);
    }
}

AIBinder* AIBinder::newLocalBinder(const AIBinder_Class* clazz, void* userData) {
    LocalNdkBinder* localBinder = new LocalNdkBinder();
    sp<AIBinder> ret = new AIBinder(clazz, userData, localBinder);
    localBinder->setAIBinder(ret);

    ret->incStrong(nullptr);
    return ret.get();
}

AIBinder* AIBinder::newFromBinder(sp<IBinder> binder) {
    if (binder == nullptr) {
        return nullptr;
    }

    // This may be a local or a remote object. If it is local, it is treating as a generic binder
    // object until associate class is called at which point it will be replaced with a reference to
    // the local binder.
    sp<AIBinder> ret = new AIBinder(nullptr /*clazz*/, nullptr /*userData*/, binder);

    if (ret == nullptr) {
        return nullptr;
    }

    ret->incStrong(nullptr);
    return ret.get();
}

sp<AIBinder> AIBinder::associateClass(const AIBinder_Class* clazz) {
    using ::android::String8;

    CHECK(clazz != nullptr);

    if (mClazz == clazz) return this;

    String8 newDescriptor(clazz->getInterfaceDescriptor());

    if (mClazz != nullptr) {
        String8 currentDescriptor(mClazz->getInterfaceDescriptor());

        if (newDescriptor == currentDescriptor) {
            LOG(ERROR) << __func__ << ": Class descriptors '" << currentDescriptor
                       << "' match during associateClass, but they are different class objects. "
                          "Class descriptor collision?";
            return nullptr;
        }

        LOG(ERROR) << __func__
                   << ": Class cannot be associated on object which already has a class. Trying to "
                      "associate to '"
                   << newDescriptor.c_str() << "' but already set to '" << currentDescriptor.c_str()
                   << "'.";
        return nullptr;
    }

    String8 descriptor(clazz->getInterfaceDescriptor());

    if (clazz->getInterfaceDescriptor() != mBinder->getInterfaceDescriptor()) {
        LOG(ERROR) << __func__ << ": Expecting binder to have class '" << newDescriptor.c_str()
                   << "' but remote descriptor is actually '" << descriptor.c_str() << "'.";
        return nullptr;
    }

    // The descriptor matches, so this is guaranteed to be a LocalNdkBinder. An error here can occur
    // if there is a conflict between descriptors (two unrelated classes define the same
    // descriptor), but this should never happen.
    LocalNdkBinder* localBinder = static_cast<LocalNdkBinder*>(mBinder->localBinder());
    if (localBinder != nullptr) {
        sp<AIBinder> ret = localBinder->getAIBinder().promote();

        return ret;
    }

    // This is a remote object
    mClazz = clazz;

    return this;
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
        LOG(ERROR) << __func__ << ": Must provide class to construct local binder.";
        return nullptr;
    }

    void* userData = clazz->onCreate(args);
    return AIBinder::newLocalBinder(clazz, userData);
}

bool AIBinder_isRemote(AIBinder* binder) {
    if (binder == nullptr) {
        return true;
    }

    return binder->isRemote();
}

void AIBinder_incStrong(AIBinder* binder) {
    if (binder == nullptr) {
        LOG(ERROR) << __func__ << ": on null binder";
        return;
    }

    binder->incStrong(nullptr);
}
void AIBinder_decStrong(AIBinder* binder) {
    if (binder == nullptr) {
        LOG(ERROR) << __func__ << ": on null binder";
        return;
    }

    binder->decStrong(nullptr);
}
int32_t AIBinder_debugGetRefCount(AIBinder* binder) {
    if (binder == nullptr) {
        LOG(ERROR) << __func__ << ": on null binder";
        return -1;
    }

    return binder->getStrongCount();
}

AIBinder* AIBinder_associateClass(AIBinder* binder, const AIBinder_Class* clazz) {
    if (binder == nullptr || clazz == nullptr) {
        return nullptr;
    }

    sp<AIBinder> result = binder->associateClass(clazz);

    // This function takes one refcount of 'binder' and delivers one refcount of 'result' to the
    // callee. First we give the callee their refcount and then take it away from binder. This is
    // done in this order in order to handle the case that the result and the binder are the same
    // object.
    if (result != nullptr) {
        AIBinder_incStrong(result.get());
    }
    AIBinder_decStrong(binder);

    return result.get();
}

const AIBinder_Class* AIBinder_getClass(AIBinder* binder) {
    if (binder == nullptr) {
        return nullptr;
    }

    return binder->getClass();
}

void* AIBinder_getUserData(AIBinder* binder) {
    if (binder == nullptr) {
        return nullptr;
    }

    return binder->getUserData();
}

binder_status_t AIBinder_prepareTransaction(AIBinder* binder, AParcel** in) {
    if (binder == nullptr || in == nullptr) {
        LOG(ERROR) << __func__ << ": requires non-null parameters.";
        return EX_NULL_POINTER;
    }
    if (!binder->isRemote()) {
        LOG(ERROR) << __func__ << ": Cannot execute transaction on a local binder.";
        return EX_ILLEGAL_STATE;
    }

    *in = new AParcel(binder);

    binder_status_t status = ::android::initRemoteNdkBinderTransaction(binder, *in);
    if (status != EX_NONE) {
        delete *in;
        *in = nullptr;
    }

    return status;
}
binder_status_t AIBinder_transact(transaction_code_t code, AIBinder* binder, AParcel* in,
                                  binder_flags_t flags, AParcel** out) {
    // This object is the input to the transaction. This function takes ownership of it and deletes
    // it.
    std::unique_ptr<AParcel> autoInDeleter(in);

    if (!isUserCommand(code)) {
        LOG(ERROR) << __func__ << ": Only user-defined transactions can be made from the NDK.";
        return EX_UNSUPPORTED_OPERATION;
    }

    if (binder == nullptr || in == nullptr || out == nullptr) {
        LOG(ERROR) << __func__ << ": requires non-null parameters.";
        return EX_NULL_POINTER;
    }

    if (in->getBinder() != binder) {
        LOG(ERROR) << __func__ << ": parcel is associated with binder object " << binder
                   << " but called with " << in->getBinder();
        return EX_ILLEGAL_STATE;
    }

    *out = new AParcel(binder);

    binder_status_t parcelStatus =
            binder->getBinder()->transact(code, *in->operator->(), (*out)->operator->(), flags);

    if (parcelStatus != EX_NONE) {
        delete *out;
        *out = nullptr;
    }

    return parcelStatus;
}

binder_status_t AIBinder_finalizeTransaction(AIBinder* binder, AParcel* out) {
    // This object is the input to the transaction. This function takes ownership of it and deletes
    // it.
    std::unique_ptr<AParcel> autoInDeleter(out);

    if (binder == nullptr || out == nullptr) {
        LOG(ERROR) << __func__ << ": requires non-null parameters.";
        return EX_NULL_POINTER;
    }

    if (out->getBinder() != binder) {
        LOG(ERROR) << __func__ << ": parcel is associated with binder object " << binder
                   << " but called with " << out->getBinder();
        return EX_ILLEGAL_STATE;
    }

    if ((*out)->dataAvail() != 0) {
        LOG(ERROR) << __func__
                   << ": Only part of this transaction was read. There is remaining data left.";
        return EX_ILLEGAL_STATE;
    }

    return EX_NONE;
}

binder_status_t AIBinder_registerAsService(AIBinder* binder, const char* instance) {
    if (binder == nullptr || instance == nullptr) {
        return EX_NULL_POINTER;
    }

    sp<IServiceManager> sm = defaultServiceManager();
    return sm->addService(::android::String16(instance), binder->getBinder());
}
AIBinder* AIBinder_getService(const char* instance) {
    if (instance == nullptr) {
        return nullptr;
    }

    sp<IServiceManager> sm = defaultServiceManager();
    sp<IBinder> binder = sm->getService(::android::String16(instance));

    return AIBinder::newFromBinder(binder);
}
