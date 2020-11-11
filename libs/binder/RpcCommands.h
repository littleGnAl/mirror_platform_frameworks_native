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
#pragma once

namespace android {

// This file defines the top level protocol for RPC transactions

#pragma clang diagnostic push
#pragma clang diagnostic error "-Wpadded"

enum : uint32_t {
    RPC_COMMAND_TRANSACT = 1,
    // FIXME: add
    // - RPC_COMMAND_ADD_THREAD
    // ...
};

struct RpcCommand {
    uint32_t command;  // RPC_COMMAND_*
    uint32_t bodySize;

    uint32_t reserved[2];
};

#pragma clang diagnostic pop

} // namespace android
