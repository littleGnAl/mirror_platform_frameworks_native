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

#include "../Utils.h"

#include <openssl/rand.h>
#include <string.h>

using android::base::ErrnoError;
using android::base::Result;

namespace android {

void zeroMemory(uint8_t* data, size_t size) {
    memset(data, 0, size);
}

Result<void> setNonBlocking(android::base::borrowed_fd fd) {
    // TODO: do something Trusty-specific
    return {};
}

status_t getRandomBytes(std::vector<uint8_t>& data) {
    int res = RAND_bytes(data.data(), data.size());
    return res == 1 ? OK : UNKNOWN_ERROR;
}

} // namespace android
