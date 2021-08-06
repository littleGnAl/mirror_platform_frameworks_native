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

#define LOG_TAG "RpcTransport"
#include <log/log.h>

#include <poll.h>

#include <binder/RpcTransport.h>

#include "FdTrigger.h"
#include "RpcState.h"

namespace android {

status_t RpcTransport::interruptableWriteFully(FdTrigger* fdTrigger, const void* data,
                                               size_t size) {
    const uint8_t* buffer = reinterpret_cast<const uint8_t*>(data);
    const uint8_t* end = buffer + size;

    MAYBE_WAIT_IN_FLAKE_MODE;

    status_t status;
    while ((status = triggerablePoll(fdTrigger, POLLOUT)) == OK) {
        auto writeSize = this->send(buffer, end - buffer);
        if (!writeSize.ok()) {
            LOG_RPC_DETAIL("RpcTransport::send(): %s", writeSize.error().message().c_str());
            return writeSize.error().code() == 0 ? UNKNOWN_ERROR : -writeSize.error().code();
        }

        if (*writeSize == 0) return DEAD_OBJECT;

        buffer += *writeSize;
        if (buffer == end) return OK;
    }
    return status;
}

status_t RpcTransport::interruptableReadFully(FdTrigger* fdTrigger, void* data, size_t size) {
    uint8_t* buffer = reinterpret_cast<uint8_t*>(data);
    uint8_t* end = buffer + size;

    MAYBE_WAIT_IN_FLAKE_MODE;

    status_t status;
    while ((status = triggerablePoll(fdTrigger, POLLIN)) == OK) {
        auto readSize = this->recv(buffer, end - buffer);
        if (!readSize.ok()) {
            LOG_RPC_DETAIL("RpcTransport::recv(): %s", readSize.error().message().c_str());
            return readSize.error().code() == 0 ? UNKNOWN_ERROR : -readSize.error().code();
        }

        if (*readSize == 0) return DEAD_OBJECT; // EOF

        buffer += *readSize;
        if (buffer == end) return OK;
    }
    return status;
}

} // namespace android
