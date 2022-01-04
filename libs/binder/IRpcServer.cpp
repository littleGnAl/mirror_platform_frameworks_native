/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "IRpcServer"

#include <inttypes.h>
#include <vector>

#include <binder/RpcServer.h>
#include <binder/RpcTransportRaw.h>
#include <log/log.h>

#include "FdTrigger.h"
#include "RpcWireFormat.h"

namespace android {

status_t IRpcServer::establishConnectionHandshake(RpcTransport* transport, FdTrigger* fdTrigger,
                                                  std::optional<uint32_t> serverProtocolVersion,
                                                  IRpcServer::EstablishConnectionResult* result) {
    LOG_ALWAYS_FATAL_IF(result == nullptr);

    status_t status = OK;

    RpcConnectionHeader header;
    status = transport->interruptableReadFully(fdTrigger, &header, sizeof(header), {});
    if (status != OK) {
        ALOGE("Failed to read ID for client connecting to RPC server: %s",
              statusToString(status).c_str());
        return status;
    }

    std::vector<uint8_t> sessionId;
    if (header.sessionIdSize > 0) {
        if (header.sessionIdSize == kSessionIdBytes) {
            sessionId.resize(header.sessionIdSize);
            status = transport->interruptableReadFully(fdTrigger, sessionId.data(),
                                                       sessionId.size(), {});
            if (status != OK) {
                ALOGE("Failed to read session ID for client connecting to RPC server: %s",
                      statusToString(status).c_str());
                return status;
            }
        } else {
            ALOGE("Malformed session ID. Expecting session ID of size %zu but got %" PRIu16,
                  kSessionIdBytes, header.sessionIdSize);
            return BAD_VALUE;
        }
    }

    result->sessionId = std::move(sessionId);
    result->protocolVersion =
            std::min(header.version, serverProtocolVersion.value_or(RPC_WIRE_PROTOCOL_VERSION));
    result->incoming = header.options & RPC_CONNECTION_OPTION_INCOMING;
    result->requestingNewSession = result->sessionId.empty();

    if (result->requestingNewSession) {
        RpcNewSessionResponse response{
                .version = result->protocolVersion,
        };

        status = transport->interruptableWriteFully(fdTrigger, &response, sizeof(response), {});
        if (status != OK) {
            ALOGE("Failed to send new session response: %s", statusToString(status).c_str());
            return status;
        }
    }

    return status;
}

} // namespace android
