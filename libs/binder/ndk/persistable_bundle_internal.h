/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <android/persistable_bundle.h>
#include <utils/String8.h>

//  take a vector and put the contents into a buffer.
//  return the size of the contents.
//  This may not put all of the contents into the buffer if the buffer is not
//  large enough.
template <typename T>
size_t getVecInternal(const std::vector<T>& inVec, T* _Nullable buffer, size_t bufferSizeBytes) {
    size_t num = inVec.size();
    size_t numAvailable = bufferSizeBytes / sizeof(T);
    size_t numFill = numAvailable < num ? numAvailable : num;

    if (numFill > 0 && buffer) {
        for (size_t i = 0; i < numFill; i++) {
            buffer[i] = inVec[i];
        }
    }
    return num * sizeof(T);
}

//  take a vector or a set of String16 and put the contents into a char** buffer.
//  return the size of the contents.
//  This may not put all of the contents into the buffer if the buffer is not
//  large enough.
//  The strings are duped with a user supplied callback
template <typename T>
ssize_t getStringsInternal(const T& strings, char* _Nullable* _Nullable buffer,
                           size_t bufferSizeBytes,
                           APersistableBundle_stringAllocator stringAllocator,
                           void* _Nullable context) {
    size_t num = strings.size();
    size_t numAvailable = bufferSizeBytes / sizeof(char*);
    size_t numFill = numAvailable < num ? numAvailable : num;
    if (!stringAllocator) {
        return -1;
    }

    if (numFill > 0 && buffer) {
        size_t i = 0;
        for (const auto& val : strings) {
            android::String8 tmp8 = android::String8(val);
            buffer[i] = stringAllocator(tmp8.bytes() + 1, context);
            if (buffer[i] == nullptr) {
                return -1;
            }
            strncpy(buffer[i], tmp8.c_str(), tmp8.bytes() + 1);
            i++;
            if (i > numFill - 1) {
                // buffer is too small to keep going or this is the end of the
                // set
                break;
            }
        }
    }
    return num * sizeof(char*);
}
