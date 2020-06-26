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
#include <IBinderFuzzFunctions.h>
#include <commonFuzzHelpers.h>
#include <fuzzer/FuzzedDataProvider.h>

#include <binder/BpBinder.h>
#include <binder/IServiceManager.h>

namespace android {

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FuzzedDataProvider fdp(data, size);
    int32_t handle = fdp.ConsumeIntegralInRange<int32_t>(0, 1024);

    // Pull in a binder object from service manager if there are any active services.
    sp<IServiceManager> sm = defaultServiceManager();
    auto service_list = sm->listServices(fdp.ConsumeIntegral<int>());
    sp<BpBinder> bpbinder;
    if (service_list.size() == 0) {
        bpbinder = BpBinder::create(handle);
    } else {
        // TODO(corbin.souffrant@leviathansecurity.com): Cant figure out how to cast this... is it
        // possible?
        bpbinder = static_cast<BpBinder *>(
                sm->getService(
                          service_list[fdp.ConsumeIntegralInRange<size_t>(0,
                                                                          service_list.size() - 1)])
                        .get());
    }

    if (bpbinder == nullptr) return 0;

    while (fdp.remaining_bytes() > 0) {
        if (fdp.ConsumeBool()) {
            callArbitraryFunction(&fdp, bpBinder_operations, bpbinder.get());
        } else {
            callArbitraryFunction(&fdp, IBinder_operations, bpbinder.get());
        }
    }

    // Clean up possible leftover memory.
    wp<IBinder::DeathRecipient> outRecipient(nullptr);
    bpbinder->sendObituary();
    bpbinder->unlinkToDeath(nullptr, reinterpret_cast<void *>(&kBpBinderCookie), 0, &outRecipient);
    return 0;
}
} // namespace android
