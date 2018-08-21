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

#include <binder/IBinder.h>

struct AIBinder {
    static AIBinder* newLocalBinder(const AIBinder_Class* clazz, AIBinder_Class_Impl impl);

    // May or may not be local.
    static AIBinder* newFromBinder(::android::sp<::android::IBinder> binder);

    // Verifies that a class is not already set and that the descriptor is valid.
    //
    // clazz cannot be nullptr.
    bool setClass(const AIBinder_Class* clazz);

    const AIBinder_Class* getClass() const { return mClazz; }
    AIBinder_Class_Impl getImpl() { return mImpl; }
    const ::android::sp<::android::IBinder>& getBinder() const { return mBinder; }

    bool isRemote() const { return mIsRemote; }

private:
    AIBinder(const AIBinder_Class* clazz, AIBinder_Class_Impl impl,
             ::android::sp<::android::IBinder> binder)
          : mIsRemote(binder->remoteBinder() != nullptr),
            mClazz(clazz),
            mImpl(impl),
            mBinder(binder) {}

    // FIXME: make/add const versions of 'localBinder' and 'remoteBinder'?
    bool mIsRemote;

    // AIBinder instance is instance of this class
    //
    // Must be set using setClass in order to transact on a binder which is remote.
    const AIBinder_Class* mClazz;

    // Can contain implementation if this is a local binder. This can still be nullptr for a remote
    // binder. If it is nullptr, the implication is the implementation state is entirely external to
    // this object and the functionality provided in the AIBinder_Class is sufficient.
    AIBinder_Class_Impl mImpl;

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
