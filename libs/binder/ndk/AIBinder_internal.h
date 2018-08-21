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
    static AIBinder* newRemoteBinder(::android::sp<::android::IBinder> remoteBinder);

    const AIBinder_Class* getClass() const { return mClazz; }
    // FIXME: documentation
    bool setClass(const AIBinder_Class* clazz);
    AIBinder_Class_Impl getImpl() { return mImpl; }
    const ::android::sp<::android::IBinder>& getBinder() const { return mBinder; }

private:
    AIBinder(const AIBinder_Class* clazz, AIBinder_Class_Impl impl,
             ::android::sp<::android::IBinder> binder)
          : mClazz(clazz), mImpl(impl), mBinder(binder) {}

    // AIBinder instance is instance of this class if it is loaded in this process
    const AIBinder_Class* mClazz;

    // implementation if local binder
    AIBinder_Class_Impl mImpl;

    // remote or local binder object
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
