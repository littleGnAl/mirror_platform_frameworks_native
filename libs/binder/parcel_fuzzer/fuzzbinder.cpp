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

#include <fuzzbinder/fuzzbinder.h>

#include <fuzzbinder/random_parcel.h>

namespace android {

static void randomTransaction(const sp<IBinder>& binder, FuzzedDataProvider&& provider) {
    uint32_t code = provider.ConsumeIntegral<uint32_t>();
    uint32_t flags = provider.ConsumeIntegral<uint32_t>();
    Parcel parcel;
    fillRandomParcel(&parcel, std::move(provider));

    // reply is only ever null for in-process transactions, which we don't care
    // about for fuzzing
    Parcel reply;
    binder->transact(code, parcel, &reply, flags);
}

void fuzzBinder(const sp<IBinder>& binder, const uint8_t* data, size_t size) {
    FuzzedDataProvider provider(data, size);

    while (provider.remaining_bytes() > 0) {
        size_t size = provider.ConsumeIntegralInRange<size_t>(0, provider.remaining_bytes());

        std::vector<uint8_t> bytes = provider.ConsumeBytes<uint8_t>(size);
        randomTransaction(binder, FuzzedDataProvider(bytes.data(), bytes.size()));
    }
}

}  // android
