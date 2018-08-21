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

AIBinder_Class_Impl IFoo_Class_onCreate(void* args) {
    IFoo* foo = static_cast<IFoo*>(args);
    // FIXME: sanity test it's a foo
    return static_cast<AIBinder_Class_Impl>(foo);
}

void IFoo_Class_onDestroy(AIBinder_Class_Impl impl) {
    IFoo* foo = static_cast<IFoo*>(impl);
    delete foo;
}

service_status_t IFoo_Class_onTransact(transaction_code_t code, AIBinder* binder, AParcel* in,
                                       AParcel* out) {
    transport_status_t stat = EX_NONE;

    IFoo* foo = static_cast<IFoo*>(AIBinder_getImpl(binder));

    switch (code) {
        case IFoo::DOFOO: {
            int32_t valueIn;
            int32_t valueOut;
            stat = AParcel_readInt32(in, &valueIn);
            if (stat != EX_NONE) break;
            foo->doubleNumber(valueIn, &valueOut);
            stat = AParcel_writeInt32(out, valueOut);
            if (stat != EX_NONE) break;
        }
        default: {
            // FIXME call into parent binder
            stat = EX_UNSUPPORTED_OPERATION;
        }
    }
    return stat;
}

AIBinder_Class* kIFoo_Class =
        AIBinder_Class_define("my-special-IFoo-class", IFoo_Class_onCreate, IFoo_Class_onDestroy,
                              IFoo_Class_onTransact);

AIBinder* IFoo::newLocalBinder(IFoo* foo) {
	return AIBinder_new(kIFoo_Class, static_cast<AIBinder_Class_Impl>(foo));
}
