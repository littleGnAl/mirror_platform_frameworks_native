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

// Utility functions that dlopen()'s libbinder_tls. With these functions, libbinder can use
// RpcTransport without worrying about when to dlclose() and free raw pointers.

#pragma once

#include "RpcTransport.h"

namespace android {

// Create a RpcTransport with TLS enabled or not. Return null on error.
// This should be call after ::accept4().
std::unique_ptr<android::RpcTransport> newServerRpcTransport(bool tls,
                                                             android::base::unique_fd acceptedFd);

// Create a RpcTransport with TLS enabled or not. Return null on error.
// This should be call after ::connect().
std::unique_ptr<android::RpcTransport> newClientRpcTransport(bool tls,
                                                             android::base::unique_fd connectedFd);

} // namespace android
