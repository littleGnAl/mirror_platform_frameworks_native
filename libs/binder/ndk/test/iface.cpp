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
using ::android::wp;

const char* IFoo::kSomeInstanceName = "libbinder_ndk-test-IFoo";
const char* kIFooDescriptor = "my-special-IFoo-class";

struct IFoo_Class_Impl {
    wp<IFoo> foo;
};

void* IFoo_Class_onCreate(void* args) {
    IFoo_Class_Impl* foo = static_cast<IFoo_Class_Impl*>(args);
    // This is a foo, but we're currently not verifying that. So, the method newLocalBinder is
    // coupled with this.
    return static_cast<void*>(foo);
}

void IFoo_Class_onDestroy(void* userData) {
    delete static_cast<IFoo_Class_Impl*>(userData);
}

binder_status_t IFoo_Class_onTransact(transaction_code_t code, AIBinder* binder, const AParcel* in,
                                      AParcel* out) {
    binder_status_t stat = EX_UNSUPPORTED_OPERATION;

    sp<IFoo> foo = static_cast<IFoo_Class_Impl*>(AIBinder_getUserData(binder))->foo.promote();
    CHECK(foo != nullptr) << "Transaction made on already deleted object";

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
        AParcel* parcelIn;
        CHECK(EX_NONE == AIBinder_prepareTransaction(mBinder, &parcelIn));

        CHECK(EX_NONE == AParcel_writeInt32(parcelIn, in));

        AParcel* parcelOut;
        CHECK(EX_NONE ==
              AIBinder_transact(IFoo::DOFOO, mBinder, parcelIn, 0 /*flags*/, &parcelOut));

        int32_t out;
        CHECK(EX_NONE == AParcel_readInt32(parcelOut, &out));

        CHECK(EX_NONE == AIBinder_finalizeTransaction(mBinder, parcelOut));
        return out;
    }
};

IFoo::~IFoo() {
    AIBinder_decStrong(mBinder);
}

binder_status_t IFoo::registerAsService(const char* instance) {
    // This simple mock implementation doesn't support registering multiple times.
    CHECK(mBinder == nullptr);

    mBinder = AIBinder_new(kIFoo_Class, static_cast<void*>(new IFoo_Class_Impl{this}));

    if (mBinder == nullptr) {
        return EX_NULL_POINTER;
    }

    return AIBinder_registerAsService(mBinder, instance);
}

sp<IFoo> IFoo::getService(const char* instance) {
    AIBinder* binder = AIBinder_getService(instance);
    if (binder == nullptr) {
        return nullptr;
    }

    if (AIBinder_getClass(binder) == kIFoo_Class) {
        sp<IFoo> foo = static_cast<IFoo_Class_Impl*>(AIBinder_getUserData(binder))->foo.promote();

        if (foo == nullptr) {
            LOG(FATAL)
                    << "Local implementation of service being retrieved deleted during retrieval.";
            return nullptr;
        }

        // we always construct IFoo with an implementation
        CHECK(foo->mBinder == binder);

        // exactly one refcount to the binder is kept by IFoo
        AIBinder_decStrong(binder);

        return foo;
    }

    if (!AIBinder_setClass(binder, kIFoo_Class)) {
        AIBinder_decStrong(binder);
        return nullptr;
    }

    sp<IFoo> res = new BnFoo();
    res->mBinder = binder;
    return res;
}
