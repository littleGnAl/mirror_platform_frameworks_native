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

static inline void* AParcel_std_string_allocator(void* data, const char* str, int32_t length) {
    std::string* str = static_cast<std::string*>(data);
    str->resize(length - 1);
    return &(*str)[0];
}

static inline binder_status_t AParcel_writeString(AParcel* parcel, const std::string& str) {
    return AParcel_writeString(parcel, str.c_str(), str.size());
}

static inline binder_status_t AParcel_readString(const AParcel* parcel, std::string* str) {
    void* data = static_cast<void*>(str);
    return AParcel_readString(parcel, AParcel_std_string_allocator, data);
}

#endif // __cplusplus
