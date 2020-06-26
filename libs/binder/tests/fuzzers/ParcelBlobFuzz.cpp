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

#define LOG_TAG "Parcel"

#include <ParcelBlobFuzzFunctions.h>
#include <commonFuzzHelpers.h>
#include <fuzzer/FuzzedDataProvider.h>

namespace android {

// Fuzzer entry point.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    // Init our wrapper
    FuzzedDataProvider dataProvider(data, size);
    std::vector<std::shared_ptr<Parcel::ReadableBlob>> readableBlobVector;
    std::vector<std::shared_ptr<Parcel::WritableBlob>> writableBlobVector;

    // Call some functions
    while (dataProvider.remaining_bytes() > 0) {
        if (readableBlobVector.empty()) {
            parcelBlob_operations[0](&dataProvider, &readableBlobVector, &writableBlobVector);
        }

        if (writableBlobVector.empty()) {
            parcelBlob_operations[1](&dataProvider, &readableBlobVector, &writableBlobVector);
        }

        callArbitraryFunction(&dataProvider, parcelBlob_operations, &readableBlobVector,
                              &writableBlobVector);
    }

    return 0;
}

} // namespace android
