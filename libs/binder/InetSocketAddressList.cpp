/*
 * Copyright (C) 2021 The Android Open Source Project
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
#include "InetSocketAddressList.h"

#include <utils/Log.h>
#include <utils/String8.h>

namespace android {
InetSocketAddressList InetSocketAddressList::GetAddrInfo(const char* addr, unsigned int port) {
    addrinfo hint{
            .ai_flags = 0,
            .ai_family = AF_UNSPEC,
            .ai_socktype = SOCK_STREAM,
            .ai_protocol = 0,
    };

    addrinfo* ai_start = nullptr;
    if (int rc = getaddrinfo(addr, std::to_string(port).data(), &hint, &ai_start); 0 != rc) {
        ALOGE("Unable to resolve %s:%u: %s", addr, port, gai_strerror(rc));
        return InetSocketAddressList();
    }
    if (ai_start == nullptr) {
        ALOGE("Unable to resolve %s:%u: getaddrinfo returns null", addr, port);
        return InetSocketAddressList();
    }

    return InetSocketAddressList(ai_start, String8::format("%s:%u", addr, port).c_str());
}
} // namespace android
