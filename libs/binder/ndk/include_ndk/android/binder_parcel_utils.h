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

#pragma once

#include <android/binder_parcel.h>

#ifdef __cplusplus

#include <string>

static inline char* AParcel_std_string_allocator(void* stringData, size_t length) {
    std::string* str = static_cast<std::string*>(stringData);
    // includes space for '\0' which at the time of C++11 is UB to assume existance.
    str->resize(length);
    return &(*str)[0];
}

static inline binder_status_t AParcel_writeString(AParcel* parcel, const std::string& str) {
    return AParcel_writeString(parcel, str.c_str(), str.size());
}

static inline binder_status_t AParcel_readString(const AParcel* parcel, std::string* str) {
    void* stringData = static_cast<void*>(str);
    binder_status_t status = AParcel_readString(parcel, AParcel_std_string_allocator, stringData);

    if (status == STATUS_OK) {
        if (str->empty()) {
            return STATUS_BAD_VALUE;
        }
        str->resize(str->size() - 1); // cut off extra space for '\0'
    }

    return status;
}

#endif // __cplusplus
