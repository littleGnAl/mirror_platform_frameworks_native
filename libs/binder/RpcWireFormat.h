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

// FIXME: design for flexibility (add get version transaction or default version
//     methodology).
// FIXME: there is probably a better organizational strategy?
// FIXME: documentation

#pragma clang diagnostic push
#pragma clang diagnostic error "-Wpadded"

enum : uint32_t {
    // FIXME: needs 'get version/info' root transaction
    // FIXME: switch comments to be nicer style
    RPC_COMMAND_TRANSACT, // follows is RpcWireTransaction, if flags != oneway, reply w/ RPC_COMMAND_REPLY expected
    RPC_COMMAND_REPLY, // follows is RpcWireReply
    // FIXME: why not as SPECIAL_TRANSACT? -- too heavy?
    RPC_COMMAND_DEC_STRONG, // follows is RpcWireAddress
    // FIXME: add (though, maybe as SPECIAL_TRANSACT?)
    // - RPC_COMMAND_ADD_THREAD
    // - RPC_COMMAND_ERROR
    // ...
};

/**
 * These commands are used when the address in an RpcWireTransaction is zero'd
 * out (no address). This allows the transact/reply flow to be used for
 * additional server commands, without making the protocol for
 * transactions/replies more complicated.
 */
enum : uint32_t {
    RPC_SPECIAL_TRANSACT_GET_ROOT = 0,
};

// serialization is like:
// |RpcWireHeader|struct desginated by 'command'| (over and over again)

struct RpcWireHeader {
    uint32_t command;  // RPC_COMMAND_*
    uint32_t bodySize;

    uint32_t reserved[2];
};

// FIXME: add information about IPs, port ranges (or document why not, because
// an address is always associated with runtime state in an RpcConnection
// object)
struct RpcWireAddress {
    uint8_t address[32];
};

struct RpcWireTransaction {
    RpcWireAddress address;
    uint32_t code;
    uint32_t flags;  // FIXME: do not expose binder flags

    uint32_t reserved;

    uint8_t data[0];
};

struct RpcWireReply {
    int32_t status;  // transact return
    uint8_t data[0];
};

// FIXME: add sizeof checks

#pragma clang diagnostic pop

}  // namespace android
