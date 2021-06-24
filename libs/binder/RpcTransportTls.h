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

// Wraps the transport layer of RPC. Implementation uses TLS.

#pragma once

#include <memory>

#include <android-base/unique_fd.h>

#include "RpcTransport.h"

extern "C" {
// Create a RpcTransport with TLS enabled. Return null on error.
// Caller takes ownership of returned object.
// Note: don't use directly. You probably want newServerRpcTransport.
__attribute__((visibility("default"))) android::RpcTransport *newServerRpcTransportTls(
        android::base::unique_fd acceptedFd);

// Create a RpcTransport with TLS enabled. Return null on error.
// Caller takes ownership of returned object.
// Note: don't use directly. You probably want newClientRpcTransport.
__attribute__((visibility("default"))) android::RpcTransport *newClientRpcTransportTls(
        android::base::unique_fd connectedFd);
} // extern "C"
