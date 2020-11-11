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

// FIXME: design for flexibility
// FIXME: there is probably a better organizational strategy?
// FIXME: documentation

#pragma clang diagnostic push
#pragma clang diagnostic error "-Wpadded"

enum : uint32_t {
    RPC_COMMAND_TRANSACT, // follows is RpcTransaction
    RPC_COMMAND_REPLY, // follows is RpcReply
    RPC_COMMAND_DEC_REF, // follows is RpcAddress
    // FIXME: add
    // - RPC_COMMAND_ADD_THREAD
    // ...
};

// serialization is like:
// |RpcCommand|struct desginated by 'command'| (over and over again)

struct RpcCommand {
    uint32_t command;  // RPC_COMMAND_*
    uint32_t bodySize;

    uint32_t reserved[2];
};

struct RpcTransaction {
    int address;  // FIXME: must be larger/extensible
    uint32_t code;
    uint32_t flags;  // FIXME: do not expose binder flags

    uint32_t reserved;

    uint8_t data[0];
};

struct RpcReply {
    int32_t status;  // transact return
    uint8_t data[0];
};

// FIXME: add sizeof checks

#pragma clang diagnostic pop

} // namespace android
