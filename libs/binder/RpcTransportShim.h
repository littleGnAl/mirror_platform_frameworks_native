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

// Utility functions that wraps transport layer details.

#pragma once

#include <memory>

#include <binder/RpcSecurity.h>

#include "RpcTransport.h"

namespace android {

// Create a RpcTransportCtx with TLS enabled or not. Return null on error.
std::unique_ptr<android::RpcTransportCtx> newServerRpcTransportCtx(RpcSecurity security);

// Create a RpcTransportCtx with TLS enabled or not. Return null on error.
std::unique_ptr<android::RpcTransportCtx> newClientRpcTransportCtx(RpcSecurity security);

} // namespace android
