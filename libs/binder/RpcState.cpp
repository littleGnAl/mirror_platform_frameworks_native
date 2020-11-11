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

RpcState::RpcState() {}
RpcState::~RpcState() {}

status_t RpcState::onBinderLeaving(const sp<RpcConnection>& connection,
                                   const sp<IBinder>& binder,
                                   RpcAddress* outAddress) {
    // WARNING: the incStrong in this function is cleaned up in two places:
    // - when the client requests it, via processDecStrong
    // - when the connectionfails, via terminate

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
            node.timesSent++;
            *outAddress = addr;
            return OK;
        }
    }
    LOG_ALWAYS_FATAL_IF(isRpc, "RPC binder must have known address at this point");
    binder->incStrong(nullptr);
    // FIXME: cleanup dedupe this 1 w/ ++ above
    auto it = mNodeForAddress.insert({RpcAddress::unique(), BinderNode{
      .binder = binder,
      .timesSent = 1
    }});
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

        // implicitly have strong RPC refcount, since we received this binder
        it->second.timesRecd++;

        _l.unlock();

        // We have timesRecd RPC refcounts, but we only need to hold on to one
        // when we keep the object. All additional dec strongs are sent
        // immediately, we wait to send the last one in BpBinder::onLastDecStrong.
        (void)connection->sendDecStrong(address);

        return binder;
    }

    auto insert = mNodeForAddress.insert({address, BinderNode{}});
    LOG_ALWAYS_FATAL_IF(!insert.second, "Failed to insert binder when creating proxy");

    // Currently, all binders are assumed to be part of the same connection (no
    // device global binders in the RPC world).
    sp<IBinder> binder = BpBinder::create(connection, insert.first->first);
    insert.first->second.binder = binder;
    insert.first->second.timesRecd = 1;
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

        ALOGE("- BINDER NODE: %p times sent:%zu times recd: %zu a:%s type:%s",
              node.binder.unsafe_get(),
              node.timesSent,
              node.timesRecd,
              address.toString().c_str(),
              desc);
    }
    ALOGE("END DUMP OF RpcState");
}

void RpcState::terminate() {
    if (SHOULD_LOG_RPC_DETAIL) {
        dump();
    }

    std::lock_guard<std::mutex> _l(mNodeMutex);

    mTerminated = true;

    for (auto& [address, node] : mNodeForAddress) {
        sp<IBinder> binder = node.binder.promote();
        LOG_ALWAYS_FATAL_IF(binder == nullptr, "Binder %p expected to be owned.", binder.get());

        // FIXME: if the destructor of a binder object makes another RPC call,
        // then this could deadlock.
        for (; node.timesSent > 0; node.timesSent--) {
            binder->decStrong(nullptr);
        }
    }

    mNodeForAddress.clear();
}

// FIXME: change way we are reading/writing from socket (bufferred? io_uring?
// recv_msg?)

bool RpcState::rpcSend(const base::unique_fd& fd,
                       const char* what, const void* data, size_t size) {
    LOG_RPC_DETAIL("Sending %s on fd %d: %s", what, fd.get(), hexString(data, size).c_str());

    ssize_t sent = TEMP_FAILURE_RETRY(send(fd.get(), data, size, 0));

    // FIXME: range check (ssize_t)
    if (sent != (ssize_t) size) {
        ALOGE("Failed to send %s (sent %zd of %zu bytes) on fd %d, error: %s",
              what, sent, size, fd.get(), strerror(errno));

        terminate();  // fail hard, fail fast
        return false;
    }

    return true;
}

bool RpcState::rpcRec(const base::unique_fd& fd, const char* what, void* data, size_t size) {
    ssize_t recd = TEMP_FAILURE_RETRY(recv(fd.get(), data, size, MSG_WAITALL));

    // FIXME: range check (ssize_t)
    if (recd != (ssize_t) size) {
        terminate();  // fail hard, fail fast

        if (recd == 0 && errno == 0) {
            LOG_RPC_DETAIL("No more data when trying to read %s on fd %d", what, fd.get());
            return false;
        }

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
    // FIXME: check to make sure this is a known address? or if terminated?

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
        return DEAD_OBJECT;
    }
    if (!rpcSend(fd, "command body", transactionData.data(), transactionData.size())) {
        return DEAD_OBJECT;
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
            return DEAD_OBJECT;
        }

        if (command.command == RPC_COMMAND_REPLY) break;

        status_t status = processServerCommand(fd, connection, command);
        if (status != OK) return status;
    }

    uint8_t* data = new uint8_t[command.bodySize];

    if (!rpcRec(fd, "reply body", data, command.bodySize)) {
        return DEAD_OBJECT;
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
        if (mTerminated) return DEAD_OBJECT;
        auto it = mNodeForAddress.find(addr);
        LOG_ALWAYS_FATAL_IF(it == mNodeForAddress.end(),
                            "Sending dec strong on unknown address %s", addr.toString().c_str());
        LOG_ALWAYS_FATAL_IF(it->second.timesRecd<= 0, "Bad dec strong %s", addr.toString().c_str());

        it->second.timesRecd--;
        if (it->second.timesRecd == 0 && it->second.timesSent == 0) {
            mNodeForAddress.erase(it);
        }
    }

    RpcWireHeader cmd = {
        .command = RPC_COMMAND_DEC_STRONG,
        .bodySize = sizeof(RpcWireAddress),
    };
    if (!rpcSend(fd, "dec ref header", &cmd, sizeof(cmd))) return DEAD_OBJECT;
    if (!rpcSend(fd, "dec ref body",
                 &addr.viewRawEmbedded(), sizeof(RpcWireAddress))) return DEAD_OBJECT;
    return OK;
}

status_t RpcState::getAndExecuteCommand(const base::unique_fd& fd,
                                        const sp<RpcConnection>& connection) {
    LOG_RPC_DETAIL("getAndExecuteCommand on fd %d", fd.get());

    RpcWireHeader command;
    if (!rpcRec(fd, "command header", &command, sizeof(command))) {
        return DEAD_OBJECT;
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

    // We should always know the version of the opposing side, and since the
    // RPC-binder-level wire protocol is not self synchronizing, we have no way
    // to understand where the current command ends and the next one begins. We
    // also can't consider it a fatal error because this would allow any client
    // to kill us, so ending the connection for misbehaving client.
    ALOGE("Unknown RPC command %d - terminating connection", command.command);
    terminate();
    return DEAD_OBJECT;
}
status_t RpcState::processTransact(const base::unique_fd& fd,
                                   const sp<RpcConnection>& connection,
                                   const RpcWireHeader& command) {
    LOG_ALWAYS_FATAL_IF(command.command != RPC_COMMAND_TRANSACT, "command: %d", command.command);

    // FIXME: avoid allocating extra size here?
    std::vector<uint8_t> transactionData(command.bodySize);
    if (!rpcRec(fd, "transaction body", transactionData.data(), transactionData.size())) {
        return DEAD_OBJECT;
    }

    // FIXME: check bodySize < sizeof(RpcWireTransaction)
    RpcWireTransaction* transaction = reinterpret_cast<RpcWireTransaction*>(transactionData.data());

    status_t replyStatus = OK;
    sp<IBinder> target;
    RpcWireAddress ZERO{0};
    if (memcmp(&transaction->address, &ZERO, sizeof(RpcWireAddress)) != 0) {
        std::lock_guard<std::mutex> _l(mNodeMutex);
        // FIXME: heap allocation just for lookup
        auto addr = RpcAddress::fromRawEmbedded(&transaction->address);
        auto it = mNodeForAddress.find(addr);
        if (it == mNodeForAddress.end()) {
            ALOGE("Unknown binder address %s", addr.toString().c_str());
            dump();
            // FIXME: terminate connection? - when can this happen in practice
            // for well-behaving clients?
            replyStatus = BAD_VALUE;
        } else {
            // FIXME: assert this is a local binder (we aren't being asked to do a
            // command on a remote binder)
            target = it->second.binder.promote();
            if (target == nullptr) {
                // FIXME: make this into a fatal error
                // FIXME: combine with L248? or abstract lookup away
                ALOGE("Binder has been deleted at address %s", addr.toString().c_str());
                // FIXME: add RpcWireHeader reply of type 'ERROR' so client can get a nicer
                // error?
                replyStatus = UNKNOWN_ERROR;
            }
        }
    }

    Parcel data;
    data.setData(transaction->data, command.bodySize - offsetof(RpcWireTransaction, data));
    data.markForRpc(connection);

    Parcel reply;
    reply.markForRpc(connection);

    if (replyStatus == OK) {
        if (target) {
            replyStatus = target->transact(transaction->code, data, &reply, transaction->flags);
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

                    replyStatus = reply.writeStrongBinder(root);
                    break;
                }
                default: {
                    replyStatus = UNKNOWN_TRANSACTION;
                }
            }
        }
    }

    if (transaction->flags & IBinder::FLAG_ONEWAY) {
        if (replyStatus != OK) {
            ALOGW("Oneway call failed with error: %d", replyStatus);
        }
        return OK;
    }

    RpcWireReply rpcReply {
        .status = replyStatus,
    };

    std::vector<uint8_t> replyData(sizeof(RpcWireReply) + reply.dataSize());
    memcpy(replyData.data() + 0, &rpcReply, sizeof(RpcWireReply));
    memcpy(replyData.data() + sizeof(RpcWireReply), reply.data(), reply.dataSize());

    RpcWireHeader cmdReply {
        .command = RPC_COMMAND_REPLY,
        .bodySize = (uint32_t) replyData.size(), // FIXME: range check
    };

    if (!rpcSend(fd, "reply header", &cmdReply, sizeof(RpcWireHeader))) {
        return DEAD_OBJECT;
    }
    if (!rpcSend(fd, "reply body", replyData.data(), replyData.size())) {
        return DEAD_OBJECT;
    }
    return OK;
}

status_t RpcState::processDecStrong(const base::unique_fd& fd,
                                    const RpcWireHeader& command) {
    LOG_ALWAYS_FATAL_IF(command.command != RPC_COMMAND_DEC_STRONG, "command: %d", command.command);

    // FIXME: avoid allocating extra size here?
    std::vector<uint8_t> commandData(command.bodySize);
    if (!rpcRec(fd, "dec ref body", commandData.data(), commandData.size())) {
        return DEAD_OBJECT;
    }

    // FIXME: check bodySize < sizeof(RpcWireAddress)
    RpcWireAddress* address = reinterpret_cast<RpcWireAddress*>(commandData.data());
    // FIXME: heap allocation just for lookup
    auto addr = RpcAddress::fromRawEmbedded(address);

    std::unique_lock<std::mutex> _l(mNodeMutex);
    // FIXME: this is pasted from transact
    auto nit = mNodeForAddress.find(addr);
    if (nit == mNodeForAddress.end()) {
        ALOGE("Unknown binder address %s for dec strong.", addr.toString().c_str());
        // FIXME: terminate connection? misbehaving client
        return OK;
    }

    sp<IBinder> target = nit->second.binder.promote();

    if (target == nullptr) {
        // FIXME: log fatal
        // FIXME: combine with L248? or abstract lookup away
        ALOGE("Binder has been deleted at address %s", addr.toString().c_str());
        return OK;
    }
    if (nit->second.timesSent == 0) {
        ALOGE("No record of sending binder, but requested decStrong: %s", addr.toString().c_str());
        return OK;
    }

    // since each client has its own connection/RpcState, it alone is
    // responsible for not sending too many dec refs.

    nit->second.timesSent--;
    if (nit->second.timesSent == 0 && nit->second.timesRecd == 0) {
        // FIXME: think about implications for wp, add tests
        mNodeForAddress.erase(nit);
    }

    _l.unlock();

    target->decStrong(nullptr);

    return OK;
}

} // namespace android
