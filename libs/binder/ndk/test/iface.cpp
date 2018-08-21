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

#include <iface/iface.h>

const char* IFoo::kSomeInstanceName = "libbinder_ndk-test-IFoo";

const char* kIFooDescriptor = "my-special-IFoo-class";

AIBinder_Class_Impl IFoo_Class_onCreate(void* args) {
    IFoo* foo = static_cast<IFoo*>(args);
    // This is a foo, but we're currently not verifying that. So, the method newLocalBinder is
    // coupled with this.
    return static_cast<AIBinder_Class_Impl>(foo);
}

void IFoo_Class_onDestroy(AIBinder_Class_Impl impl) {
    IFoo* foo = static_cast<IFoo*>(impl);
    delete foo;
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

AIBinder* IFoo::newLocalBinder(IFoo* foo) {
    return AIBinder_new(kIFoo_Class, static_cast<AIBinder_Class_Impl>(foo));
}

class BnFoo : public IFoo {
public:
    BnFoo(AIBinder* binder) : mBinder(binder) {}

    virtual int32_t doubleNumber(int32_t in) {
        AParcel* parcelIn = AParcel_new();
        AParcel* parcelOut = AParcel_new();

        AParcel_writeInt32(parcelIn, in);
        AIBinder_transact(IFoo::DOFOO, mBinder, parcelIn, parcelOut, 0 /*flags*/);

        int32_t out;
        AParcel_readInt32(parcelOut, &out);

        AParcel_delete(parcelIn);
        AParcel_delete(parcelOut);

        return out;
    }

private:
    AIBinder* mBinder;
};

IFoo* IFoo::getService(const char* instance) {
    AIBinder* binder = AIBinder_get(instance);
    if (binder == nullptr) {
        return nullptr;
    }

    if (!AIBinder_setClass(binder, kIFoo_Class)) {
        AIBinder_delete(binder);
        return nullptr;
    }

    return new BnFoo(binder);
}
