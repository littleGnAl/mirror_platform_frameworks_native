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

#define LOG_TAG "RpcTransportShim"
#include <log/log.h>

#include "RpcTransportShim.h"

#include <dlfcn.h>

#include <memory>

#include "RpcTransportRaw.h"

namespace android {

std::unique_ptr<RpcTransportCtx> newServerRpcTransportCtx(bool tls) {
    if (tls) {
        LOG_ALWAYS_FATAL("TLS not supported yet.");
    }
    return newRpcTransportCtxRaw();
}

std::unique_ptr<RpcTransportCtx> newClientRpcTransportCtx(bool tls) {
    if (tls) {
        LOG_ALWAYS_FATAL("TLS not supported yet.");
    }
    return newRpcTransportCtxRaw();
}

} // namespace android
