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

#include <android-base/logging.h>
#include <iface/iface.h>

using ::android::sp;

const char* IFoo::kSomeInstanceName = "libbinder_ndk-test-IFoo";
const char* kIFooDescriptor = "my-special-IFoo-class";

AIBinder_Class_Impl IFoo_Class_onCreate(void* args) {
    IFoo* foo = static_cast<IFoo*>(args);
    // This is a foo, but we're currently not verifying that. So, the method newLocalBinder is
    // coupled with this.
    return static_cast<AIBinder_Class_Impl>(foo);
}

void IFoo_Class_onDestroy(AIBinder_Class_Impl /*impl*/) {
    // FIXME: we should have the infra destroy our object, not the other way around
}

binder_status_t IFoo_Class_onTransact(transaction_code_t code, AIBinder* binder, const AParcel* in,
                                      AParcel* out) {
    binder_status_t stat = EX_UNSUPPORTED_OPERATION;

    IFoo* foo = static_cast<IFoo*>(AIBinder_getImpl(binder));

    switch (code) {
        case IFoo::DOFOO: {
            int32_t valueIn;
            stat = AParcel_readInt32(in, &valueIn);
            if (stat != EX_NONE) break;
            int32_t valueOut = foo->doubleNumber(valueIn);
            stat = AParcel_writeInt32(out, valueOut);
            break;
        }
    }

    return stat;
}

AIBinder_Class* kIFoo_Class = AIBinder_Class_define(kIFooDescriptor, IFoo_Class_onCreate,
                                                    IFoo_Class_onDestroy, IFoo_Class_onTransact);

class BnFoo : public IFoo {
public:
    BnFoo() {}

    virtual int32_t doubleNumber(int32_t in) {
        // FIXME: read return values

        AParcel* parcelIn;
        (void)AIBinder_prepareTransaction(mBinder, &parcelIn);

        (void)AParcel_writeInt32(parcelIn, in);

        AParcel* parcelOut;
        if (0 != AIBinder_transact(IFoo::DOFOO, mBinder, parcelIn, 0 /*flags*/, &parcelOut)) {
            return -1;
        }

        int32_t out;
        (void)AParcel_readInt32(parcelOut, &out);

        (void)AIBinder_finalizeTransaction(mBinder, parcelOut);

        return out;
    }
};

IFoo::~IFoo() {
    AIBinder_decStrong(mBinder);
}

binder_status_t IFoo::registerAsService(const char* instance) {
    // This simple mock implementation doesn't support registering multiple times.
    CHECK(mBinder == nullptr);

    mBinder = AIBinder_new(kIFoo_Class, static_cast<AIBinder_Class_Impl>(this));

    if (mBinder == nullptr) {
        return EX_NULL_POINTER;
    }

    return AIBinder_register(mBinder, instance);
}

sp<IFoo> IFoo::getService(const char* instance) {
    AIBinder* binder = AIBinder_get(instance);
    if (binder == nullptr) {
        return nullptr;
    }

    if (AIBinder_getClass(binder) == kIFoo_Class) {
        sp<IFoo> impl = static_cast<IFoo*>(AIBinder_getImpl(binder));

        // we always construct IFoo with an implementation
        CHECK(impl != nullptr) << "local implementation missing";
        CHECK(impl->mBinder == binder);

        AIBinder_decStrong(binder);

        return impl;
    }

    if (!AIBinder_setClass(binder, kIFoo_Class)) {
        AIBinder_decStrong(binder);
        return nullptr;
    }

    sp<IFoo> res = new BnFoo();
    res->mBinder = binder;
    return res;
}
