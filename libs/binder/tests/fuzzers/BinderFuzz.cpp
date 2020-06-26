/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <BinderFuzzFunctions.h>
#include <IBinderFuzzFunctions.h>
#include <fuzzer/FuzzedDataProvider.h>

#include <binder/Binder.h>

namespace android {

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    sp<IBinder> bbinder = new BBinder();
    
    while (fdp.remaining_bytes() > 0) {
      if (fdp.ConsumeBool()) {
          uint8_t function_id = fdp.ConsumeIntegralInRange<uint8_t>(0, bBinder_operations.size() - 1);
          bBinder_operations[function_id](&fdp, reinterpret_cast<BBinder *>(bbinder.get()));
        } else {
          uint8_t function_id =
            fdp.ConsumeIntegralInRange<uint8_t>(0, IBinder_operations.size() - 1);
          IBinder_operations[function_id](&fdp, bbinder.get());
      }     
    }

    return 0;
}
} // namespace android
