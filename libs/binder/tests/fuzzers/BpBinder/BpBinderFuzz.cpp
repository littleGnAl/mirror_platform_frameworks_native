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

#include <BpBinderFuzzFunctions.h>
#include <binder/BpBinder.h>
#include <fuzzer/FuzzedDataProvider.h>
#include "tests/fuzzers/include/commonFuzzHelpers.h"

namespace android {

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    int32_t handle = fdp.ConsumeIntegralInRange<int32_t>(0, 1024);
    sp<BpBinder> bpbinder = BpBinder::create(handle);

    if (bpbinder == nullptr) return 0;

    while (fdp.remaining_bytes() > 0) {
        uint8_t function_id =
                fdp.ConsumeIntegralInRange<uint8_t>(0, bpBinder_operations.size() - 1);
        bpBinder_operations[function_id](&fdp, bpbinder.get());
    }

    return 0;
}
} // namespace android
