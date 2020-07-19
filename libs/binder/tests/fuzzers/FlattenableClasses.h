/*
 * Copyright 2020 The Android Open Source Project
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

#ifndef BINDER_FUZZ_FLATTENABLE_H_
#define BINDER_FUZZ_FLATTENABLE_H_

#include <binder/Parcel.h>

namespace android {

struct FuzzFlattenable : Flattenable<FuzzFlattenable> {
    FuzzFlattenable() = default;
    explicit FuzzFlattenable(int32_t v) : value(v) {}

    // Flattenable protocol
    size_t getFlattenedSize() const { return sizeof(value); }
    size_t getFdCount() const { return 0; }
    status_t flatten(void*& /*buffer*/, size_t& /*size*/, int*& /*fds*/, size_t& /*count*/) const {
        return NO_ERROR;
    }
    status_t unflatten(void const*& /*buffer*/, size_t& /*size*/, int const*& /*fds*/,
                       size_t& /*count*/) {
        return NO_ERROR;
    }

    int32_t value = 0;
};

struct FuzzLightFlattenable : LightFlattenablePod<FuzzLightFlattenable> {
    FuzzLightFlattenable() = default;
    explicit FuzzLightFlattenable(int32_t v) : value(v) {}
    int32_t value = 0;
};

} // namespace android

#endif // BINDER_FUZZ_FLATTENABLE_H_
