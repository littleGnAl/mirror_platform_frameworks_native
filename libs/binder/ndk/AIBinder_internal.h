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

#include <binder/AIBinder.h>
#include "AIBinder_internal.h"

#include <atomic>

#include <binder/IBinder.h>

inline bool isUserCommand(int32_t code) {
    return code >= FIRST_CALL_TRANSACTION && code <= LAST_CALL_TRANSACTION;
}

struct AIBinder : public virtual ::android::RefBase {
    static AIBinder* newLocalBinder(const AIBinder_Class* clazz, void* userData);

    // May or may not be local.
    static AIBinder* newFromBinder(::android::sp<::android::IBinder> binder);

    // This returns an AIBinder object with this class associated. If the class is already
    // associated, 'this' will be returned. If there is a local AIBinder implementation, that will
    // be returned. If this is a remote object, the class will be associated and this will be ready
    // to be used for transactions.
    ::android::sp<AIBinder> associateClass(const AIBinder_Class* clazz);

    const AIBinder_Class* getClass() const { return mClazz; }
    void* getUserData() { return mUserData; }
    const ::android::sp<::android::IBinder>& getBinder() const { return mBinder; }

    bool isRemote() const { return mIsRemote; }

private:
    AIBinder(const AIBinder_Class* clazz, void* userData, ::android::sp<::android::IBinder> binder);
    virtual ~AIBinder();

    // FIXME: make/add const versions of 'localBinder' and 'remoteBinder' on IBinder?
    bool mIsRemote;

    // AIBinder instance is instance of this class for a local object. In order to transact on a
    // remote object, this also must be set for simplicity (although right now, only the
    // interfaceDescriptor from it is used).
    const AIBinder_Class* mClazz;

    // Can contain implementation if this is a local binder. This can still be nullptr for a remote
    // binder. If it is nullptr, the implication is the implementation state is entirely external to
    // this object and the functionality provided in the AIBinder_Class is sufficient.
    void* mUserData;

    ::android::sp<::android::IBinder> mBinder;
};

struct AIBinder_Class {
    AIBinder_Class(const char* interfaceDescriptor, AIBinder_Class_onCreate onCreate,
                   AIBinder_Class_onDestroy onDestroy, AIBinder_Class_onTransact onTransact);

    const ::android::String16& getInterfaceDescriptor() const { return mInterfaceDescriptor; }

    const AIBinder_Class_onCreate onCreate;
    const AIBinder_Class_onDestroy onDestroy;
    const AIBinder_Class_onTransact onTransact;

private:
    // This must be a String16 since BBinder virtual getInterfaceDescriptor returns a reference to
    // one.
    const ::android::String16 mInterfaceDescriptor;
};
