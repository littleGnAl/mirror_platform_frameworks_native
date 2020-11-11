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

#define LOG_TAG "RpcState"

#include "RpcState.h"

#include <binder/BpBinder.h>
#include <binder/RpcServer.h>

#include "RpcWireFormat.h"

namespace android {

// FIXME: get libbinder completely off of TextOutput, and merge this with the
// Debug stuff?
static std::string hexString(const void* bytes, size_t len) {
    if (bytes == nullptr) return "<null>";

    const uint8_t* bytes8 = static_cast<const uint8_t*>(bytes);
    char chars[] = "0123456789abcdef";
    std::string result;
    result.resize(len * 2);

    for (size_t i = 0; i < len; i++) {
        result[2 * i] = chars[bytes8[i] >> 4];
        result[2 * i + 1] = chars[bytes8[i] & 0xf];
    }

    return result;
}

status_t RpcState::onBinderLeaving(const sp<RpcConnection>& connection,
                                   const sp<IBinder>& binder,
                                   RpcAddress* outAddress) {
    bool isRemote = binder->remoteBinder();
    bool isRpc = isRemote && binder->remoteBinder()->isRpcBinder();

    if (isRpc && binder->remoteBinder()->getPrivateAccessorForId().connection() != connection) {
        // We need to be able to send instructions over the socket for how to
        // connect to a different server, and we also need to let the host
        // process know that this is happening.
        ALOGE("Canot send binder from unrelated binder RPC connection.");
        return INVALID_OPERATION;
    }

    if (isRemote && !isRpc) {
        // Without additional work, this would have the effect of using this
        // process to proxy calls from the socket over to the other process, and
        // it would make those calls look like they come from us (not over the
        // sockets). In order to make this work transparently like binder, we
        // would instead need to send instructions over the socket for how to
        // connect to the host process, and we also need to let the host process
        // know this was happening.
        ALOGE("Cannot send binder proxy %p over sockets", binder.get());
        return INVALID_OPERATION;
    }

    std::lock_guard<std::mutex> _l(mNodeMutex);

    // FIXME: avoid O(n) lookup. By storing addresses inside of BBinder as well???
    for (auto& [addr, node] : mNodeForAddress) {
        if (binder == node.binder) {
            if (isRpc) {
                const RpcAddress& actualAddr =
                    binder->remoteBinder()->getPrivateAccessorForId().address();
                // FIXME: this is only checking integrity of data structure
                LOG_ALWAYS_FATAL_IF(addr < actualAddr, "Address mismatch");
                LOG_ALWAYS_FATAL_IF(actualAddr < addr, "Address mismatch");
            }
            binder->incStrong(nullptr);
            node.strong++;
            *outAddress = addr;
            return OK;
        }
    }
    LOG_ALWAYS_FATAL_IF(isRpc, "RPC binder must have known address at this point");
    binder->incStrong(nullptr);
    // FIXME: cleanup dedupe this 1 w/ ++ above
    auto it = mNodeForAddress.insert({RpcAddress::unique(), BinderNode{binder,1}});
    // FIXME: better organization could avoid needing this log
    LOG_ALWAYS_FATAL_IF(!it.second);

    *outAddress = it.first->first;
    return OK;
}

sp<IBinder> RpcState::onBinderEntering(const sp<RpcConnection>& connection,
                                       const RpcAddress& address) {
    std::unique_lock<std::mutex> _l(mNodeMutex);

    auto it = mNodeForAddress.find(address);
    if (it != mNodeForAddress.end()) {
        sp<IBinder> binder = it->second.binder.promote();

        // implicitly added, since we got this binder
        it->second.strong++;

        _l.unlock();

        // every proxy send is associated with an incStrong
        connection->sendDecStrong(address);

        return binder;
    }

    auto insert = mNodeForAddress.insert({address, BinderNode{}});
    LOG_ALWAYS_FATAL_IF(!insert.second, "Failed to insert binder when creating proxy");

    // currently, all binders are assumed to be part of the same connection (no
    // device global binders in the RPC world)
    sp<IBinder> binder = BpBinder::create(connection, insert.first->first);
    insert.first->second.binder = binder;
    insert.first->second.strong = 1;
    return binder;
}

size_t RpcState::countBinders() {
    std::lock_guard<std::mutex> _l(mNodeMutex);
    return mNodeForAddress.size();
}

void RpcState::dump() {
    std::lock_guard<std::mutex> _l(mNodeMutex);
    ALOGE("DUMP OF RpcState %p", this);
    ALOGE("DUMP OF RpcState (%zu nodes)", mNodeForAddress.size());
    for (const auto& [address, node] : mNodeForAddress) {
        sp<IBinder> binder = node.binder.promote();

        const char* desc;
        if (binder) {
            if (binder->remoteBinder()) {
                if (binder->remoteBinder()->isRpcBinder()) {
                    desc = "(rpc binder proxy)";
                } else {
                    desc = "(binder proxy)";
                }
            } else {
                desc = "(local binder)";
            }
        } else {
            desc = "(null)";
        }

        ALOGE("- BINDER NODE: %p s:%zu a:%s type:%s",
              node.binder.unsafe_get(),
              node.strong,
              address.toString().c_str(),
              desc);
    }
    ALOGE("END DUMP OF RpcState");
}

// FIXME: change way we are reading/writing from socket (bufferred? io_uring?
// recv_msg?)

static inline bool rpcSend(const base::unique_fd& fd,
                           const char* what, const void* data, size_t size) {
    LOG_RPC_DETAIL("Sending %s on fd %d: %s", what, fd.get(), hexString(data, size).c_str());

    ssize_t sent = TEMP_FAILURE_RETRY(send(fd.get(), data, size, 0));

    // FIXME: range check (ssize_t)
    if (sent != (ssize_t) size) {
        ALOGE("Failed to send %s (sent %zd of %zu bytes) on fd %d, error: %s",
              what, sent, size, fd.get(), strerror(errno));
        return false;
    }

    return true;
}

static inline bool rpcRec(const base::unique_fd& fd, const char* what, void* data, size_t size) {
    ssize_t recd = TEMP_FAILURE_RETRY(recv(fd.get(), data, size, MSG_WAITALL));

    // FIXME: range check (ssize_t)
    if (recd != (ssize_t) size) {
        ALOGE("Failed to read %s (received %zd of %zu bytes) on fd %d, error: %s",
              what, recd, size, fd.get(), strerror(errno));
        return false;
    } else {
        LOG_RPC_DETAIL("Received %s on fd %d: %s", what, fd.get(), hexString(data, size).c_str());
    }

    return true;
}

sp<IBinder> RpcState::getRootObject(const base::unique_fd& fd,
                                    const sp<RpcConnection>& connection) {
    Parcel data;
    data.markForRpc(connection);
    Parcel reply;

    status_t status = transact(fd, RpcAddress::zero(),
                               RPC_SPECIAL_TRANSACT_GET_ROOT, data,
                               connection, &reply, 0);
    if (status != OK) {
        ALOGE("Error getting root object: %s", statusToString(status).c_str());
        return nullptr;
    }

    return reply.readStrongBinder();
}

status_t RpcState::transact(const base::unique_fd& fd,
                            const RpcAddress& address,
                            uint32_t code,
                            const Parcel& data,
                            const sp<RpcConnection>& connection,
                            Parcel* reply,
                            uint32_t flags) {
    if (!data.isForRpc()) {
        ALOGE("Refusing to send RPC with parcel not crafted for RPC");
        return BAD_TYPE;
    }

    if (data.objectsCount() != 0) {
        ALOGE("Parcel at %p has attached objects but is being used in an RPC call", &data);
        return BAD_TYPE;
    }

    RpcWireTransaction transaction {
        .address = address.viewRawEmbedded(),
        .code = code,
        .flags = flags,
    };

    std::vector<uint8_t> transactionData(sizeof(RpcWireTransaction) + data.dataSize());
    memcpy(transactionData.data() + 0, &transaction, sizeof(RpcWireTransaction));
    memcpy(transactionData.data() + sizeof(RpcWireTransaction), data.data(), data.dataSize());

    RpcWireHeader command {
        .command = RPC_COMMAND_TRANSACT,
        .bodySize = (uint32_t) transactionData.size(), // FIXME: range check
    };

    if (!rpcSend(fd, "transact header", &command, sizeof(command))) {
        return UNKNOWN_ERROR;
    }
    if (!rpcSend(fd, "command body", transactionData.data(), transactionData.size())) {
        return UNKNOWN_ERROR;
    }

    if (flags & IBinder::FLAG_ONEWAY) {
        return OK;  // do not wait for result
    }

    LOG_ALWAYS_FATAL_IF(reply == nullptr, "Reply parcel must be used for synchronous transaction.");

    return waitForReply(fd, connection, reply);
}

static void cleanup_data(Parcel* p,
                  const uint8_t* data, size_t dataSize,
                  const binder_size_t* objects, size_t objectsCount) {
    (void)p;
    delete[] const_cast<uint8_t*>(data - offsetof(RpcWireReply, data));
    (void)dataSize;
    LOG_ALWAYS_FATAL_IF(objects != nullptr);
    LOG_ALWAYS_FATAL_IF(objectsCount, 0);
}

status_t RpcState::waitForReply(const base::unique_fd& fd,
                                const sp<RpcConnection>& connection,
                                Parcel* reply) {
    RpcWireHeader command;
    while (true) {
        if (!rpcRec(fd, "command header", &command, sizeof(command))) {
            return NOT_ENOUGH_DATA;
        }

        if (command.command == RPC_COMMAND_REPLY) break;

        status_t status = processServerCommand(fd, connection, command);
        if (status != OK) return status;
    }

    uint8_t* data = new uint8_t[command.bodySize];

    if (!rpcRec(fd, "reply body", data, command.bodySize)) {
        return NOT_ENOUGH_DATA;
    }
    // FIXME: check bodySize < sizeof(RpcWireReply)
    RpcWireReply* rpcReply = reinterpret_cast<RpcWireReply*>(data);
    if (rpcReply->status != OK) return rpcReply->status;

    reply->ipcSetDataReference(rpcReply->data,
                               command.bodySize - offsetof(RpcWireReply, data),
                               nullptr,
                               0,
                               cleanup_data);

    reply->markForRpc(connection);

    return OK;
}

status_t RpcState::sendDecStrong(const base::unique_fd& fd, const RpcAddress& addr) {
    {
        std::lock_guard<std::mutex> _l(mNodeMutex);
        auto it = mNodeForAddress.find(addr);
        LOG_ALWAYS_FATAL_IF(it == mNodeForAddress.end(),
                            "Sending dec strong on unknown address %s", addr.toString().c_str());
        LOG_ALWAYS_FATAL_IF(it->second.strong <= 0, "Bad dec strong %s", addr.toString().c_str());

        it->second.strong--;
        if (it->second.strong == 0) {
            mNodeForAddress.erase(it);
        }
    }

    RpcWireHeader cmd = {
        .command = RPC_COMMAND_DEC_STRONG,
        .bodySize = sizeof(RpcWireAddress),
    };
    if (!rpcSend(fd, "dec ref header", &cmd, sizeof(cmd))) return UNKNOWN_ERROR;
    if (!rpcSend(fd, "dec ref body",
                 &addr.viewRawEmbedded(), sizeof(RpcWireAddress))) return UNKNOWN_ERROR;
    return OK;
}

status_t RpcState::getAndExecuteCommand(const base::unique_fd& fd,
                                        const sp<RpcConnection>& connection) {
    LOG_RPC_DETAIL("getAndExecuteCommand on fd %d", fd.get());

    RpcWireHeader command;
    if (!rpcRec(fd, "command header", &command, sizeof(command))) {
        return NOT_ENOUGH_DATA;
    }

    return processServerCommand(fd, connection, command);
}

status_t RpcState::processServerCommand(const base::unique_fd& fd,
                                        const sp<RpcConnection>& connection,
                                        const RpcWireHeader& command) {
    switch (command.command) {
    case RPC_COMMAND_TRANSACT:
        return processTransact(fd, connection, command);
    case RPC_COMMAND_DEC_STRONG:
        return processDecStrong(fd, command);
    }

    ALOGE("Unknown RPC command %d", command.command);
    return UNKNOWN_ERROR;
}
status_t RpcState::processTransact(const base::unique_fd& fd,
                                   const sp<RpcConnection>& connection,
                                   const RpcWireHeader& command) {
    LOG_ALWAYS_FATAL_IF(command.command != RPC_COMMAND_TRANSACT, "command: %d", command.command);

    // FIXME: avoid allocating extra size here?
    std::vector<uint8_t> transactionData(command.bodySize);
    if (!rpcRec(fd, "transaction body", transactionData.data(), transactionData.size())) {
        return NOT_ENOUGH_DATA;
    }

    // FIXME: check bodySize < sizeof(RpcWireTransaction)
    RpcWireTransaction* transaction = reinterpret_cast<RpcWireTransaction*>(transactionData.data());

    sp<IBinder> target;

    RpcWireAddress ZERO{0};
    if (memcmp(&transaction->address, &ZERO, sizeof(RpcWireAddress)) != 0) {
        std::lock_guard<std::mutex> _l(mNodeMutex);
        // FIXME: heap allocation just for lookup
        auto addr = RpcAddress::fromRawEmbedded(&transaction->address);
        auto it = mNodeForAddress.find(addr);
        if (it == mNodeForAddress.end()) {
            ALOGE("Unknown binder address %s",
                  hexString(&transaction->address, sizeof(RpcWireAddress)).c_str());
            dump();
            return UNKNOWN_ERROR;
        }
        // FIXME: assert this is a local binder (we aren't being asked to do a
        // command on a remote binder)
        target = it->second.binder.promote();
        if (target == nullptr) {
            // FIXME: combine with L248? or abstract lookup away
            ALOGE("Binder has been deleted at address %s",
                  hexString(&transaction->address, sizeof(RpcWireAddress)).c_str());
            // FIXME: add RpcWireHeader reply of type 'ERROR' so client can get a nicer
            // error?
            return UNKNOWN_ERROR;
        }
    }

    Parcel data;
    data.setData(transaction->data, command.bodySize - offsetof(RpcWireTransaction, data));
    data.markForRpc(connection);

    Parcel reply;
    reply.markForRpc(connection);

    status_t status;
    if (target) {
        status = target->transact(transaction->code, data, &reply, transaction->flags);
    } else {
        LOG_RPC_DETAIL("Got special transaction %u", transaction->code);
        // special case for 'zero' address (special server commands)
        // FIXME: make special transact read/writes adjacent to each other
        switch(transaction->code) {
            case RPC_SPECIAL_TRANSACT_GET_ROOT: {
                sp<IBinder> root;
                sp<RpcServer> server = connection->server().promote();
                if (server) {
                    root = server->getRootObject();
                } else {
                    ALOGE("Root object requested, but no server attached.");
                }

                status = reply.writeStrongBinder(root);
                break;
            }
            default: {
                status = UNKNOWN_TRANSACTION;
            }
        }

    }

    if (transaction->flags & IBinder::FLAG_ONEWAY) {
        if (status != OK) {
            ALOGW("Oneway call failed with error: %d", status);
        }
        return OK;
    }

    RpcWireReply rpcReply {
        .status = status,
    };

    std::vector<uint8_t> replyData(sizeof(RpcWireReply) + reply.dataSize());
    memcpy(replyData.data() + 0, &rpcReply, sizeof(RpcWireReply));
    memcpy(replyData.data() + sizeof(RpcWireReply), reply.data(), reply.dataSize());

    RpcWireHeader cmdReply {
        .command = RPC_COMMAND_REPLY,
        .bodySize = (uint32_t) replyData.size(), // FIXME: range check
    };

    if (!rpcSend(fd, "reply header", &cmdReply, sizeof(RpcWireHeader))) {
        return UNKNOWN_ERROR;
    }
    if (!rpcSend(fd, "reply body", replyData.data(), replyData.size())) {
        return UNKNOWN_ERROR;
    }
    return OK;
}

status_t RpcState::processDecStrong(const base::unique_fd& fd,
                                 const RpcWireHeader& command) {
    LOG_ALWAYS_FATAL_IF(command.command != RPC_COMMAND_DEC_STRONG, "command: %d", command.command);

    // FIXME: avoid allocating extra size here?
    std::vector<uint8_t> commandData(command.bodySize);
    if (!rpcRec(fd, "dec ref body", commandData.data(), commandData.size())) {
        return NOT_ENOUGH_DATA;
    }

    // FIXME: check bodySize < sizeof(RpcWireAddress)
    RpcWireAddress* address = reinterpret_cast<RpcWireAddress*>(commandData.data());
    // FIXME: heap allocation just for lookup
    auto addr = RpcAddress::fromRawEmbedded(address);

    std::unique_lock<std::mutex> _l(mNodeMutex);
    // FIXME: this is pasted from transact
    auto nit = mNodeForAddress.find(addr);
    if (nit == mNodeForAddress.end()) {
        ALOGE("Unknown binder address %s", addr.toString().c_str());
        return UNKNOWN_ERROR;
    }

    sp<IBinder> target = nit->second.binder.promote();

    if (target == nullptr) {
        // FIXME: combine with L248? or abstract lookup away
        ALOGE("Binder has been deleted at address %s",
              hexString(address, sizeof(RpcWireAddress)).c_str());
        return UNKNOWN_ERROR;
    }
    if (nit->second.strong == 0) {
        ALOGE("Binder does not have strong count at address %s",
              hexString(address, sizeof(RpcWireAddress)).c_str());
        return UNKNOWN_ERROR;
    }

    // since each client has its own connection/RpcState, it alone is
    // responsible for not sending too many dec refs.

    nit->second.strong--;
    if (nit->second.strong == 0) {
        // FIXME: think about implications for wp, add tests
        mNodeForAddress.erase(nit);
    }

    _l.unlock();
    target->decStrong(nullptr);

    return OK;
}

} // namespace android
