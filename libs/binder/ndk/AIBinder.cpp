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

#include "AStatus_internal.h"

// FIXME
// #include <binder/Binder.h>
// using ::android::Parcel;

struct AIBinder {
    const AIBinder_Class* clazz; // AIBinder instance is instance of this class
    AIBinder_Class_Impl impl;
};

struct AIBinder_Class {
    AIBinder_Class_onCreate onCreate = nullptr;
    AIBinder_Class_onDestroy onDestroy = nullptr;
    AIBinder_Class_onTransact onTransact = nullptr;
};

AIBinder_Class* AIBinder_Class_define(AIBinder_Class_onCreate onCreate,
                                      AIBinder_Class_onDestroy onDestroy,
                                      AIBinder_Class_onTransact onTransact) {
    if (onCreate == nullptr || onDestroy == nullptr || onTransact == nullptr) {
        return nullptr;
    }

    AIBinder_Class* ret = new AIBinder_Class;
    ret->onCreate = onCreate;
    ret->onDestroy = onDestroy;
    ret->onTransact = onTransact;
    return ret;
}

AIBinder* AIBinder_new(const AIBinder_Class* clazz, void* args) {
    if (clazz == nullptr) {
        return nullptr;
    }

    AIBinder_Class_Impl impl = clazz->onCreate(args);

    AIBinder* ret = new AIBinder;
    ret->clazz = clazz;
    ret->impl = impl;
    return ret;
}

AStatus* AIBinder_transact(transaction_code_t code, AIBinder* binder, binder_flags_t flags,
                           AParcel* in, AParcel* out) {
    if (binder == nullptr || in == nullptr || out == nullptr) {
        return AStatus_newTransportSpecific(EX_NULL_POINTER);
    }

    (void)flags;

    // FIXME: actually transact
    service_status_t parcelStatus = binder->clazz->onTransact(code, binder, in, out);

    if (parcelStatus != EX_NONE) {
        return AStatus_newServiceSpecific(parcelStatus);
    }

    return AStatus_newOk();
}

// FIXME: should this be visible in the NDK API?
AStatus* AIBinder_register(AIBinder* binder, char* instance) {
    if (binder == nullptr || instance == nullptr) {
        return AStatus_newTransportSpecific(EX_NULL_POINTER);
    }

    // FIXME: do et
    return AStatus_newOk();
}
AIBinder_Class_Impl AIBinder_getImpl(AIBinder* binder) {
    if (binder == nullptr) {
        return nullptr;
    }

    return binder->impl;
}
