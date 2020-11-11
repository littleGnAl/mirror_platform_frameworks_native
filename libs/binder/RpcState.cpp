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

#include "RpcWireFormat.h"

namespace android {

// FIXME: get libbinder completely off of TextOutput, and merge this with the
// Debug.cpp stuff?
std::string hexString(const void* bytes, size_t len) {
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

// FIXME: BEGIN RPC ADDRESS STUFF - should move to its own class

// FIXME: hello !
bool operator< (const RpcAddress& lhs, const RpcAddress& rhs) {
    return std::memcmp(lhs.get(), rhs.get(), sizeof(RpcWireAddress)) < 0;
}
std::string rwaToString(const RpcWireAddress& rwa) {
    return hexString(&rwa, sizeof(RpcWireAddress));
}
std::string rwaToString(const RpcAddress& rwa) {
    return hexString(rwa.get(), sizeof(RpcWireAddress));
}
RpcAddress rwaNew() {
    // FIXME: use cryptographically secure way to make these or otherwise
    // delegate to a centralized server
    static bool hackOnce = [](){srand(getpid() + time(0)); return true;}();
    (void) hackOnce;
    auto addr = std::make_shared<RpcWireAddress>();
    for (size_t i = 0; i < sizeof(addr->address); i++) {
        addr->address[i] = (uint8_t)rand();
    }
    ALOGE("Creating new address: %s", rwaToString(addr).c_str());
    return addr;
}

// FIXME: END RPC ADDRESS STUFF

void RpcState::setRootObject(const sp<IBinder>& binder) {
    // Anyone can get ahold of a root object, so there should only have one object
    // needing to deal with that level of access.
    LOG_ALWAYS_FATAL_IF(mRootObject != nullptr, "There can only be one root object.");

    mRootObject = binder;
}

status_t RpcState::onBinderLeaving(const sp<RpcConnection>& connection, const sp<IBinder>& binder, RpcAddress* outAddress) {
    // FIXME: also check to make sure that the binder is from this connection
    bool isRemote = binder->remoteBinder();
    bool isRpc = isRemote && binder->remoteBinder()->isRpcBinder();

    if (isRpc && binder->remoteBinder()->connection() != connection) {
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
                LOG_ALWAYS_FATAL_IF(addr != binder->remoteBinder()->address(), "Address mismatch");
            }
            binder->incStrong(nullptr);
            node.strong++;
            *outAddress = addr;
            return OK;
        }
    }
    LOG_ALWAYS_FATAL_IF(isRpc, "RPC binder must have known address at this point");
    binder->incStrong(nullptr);
    auto it = mNodeForAddress.insert({rwaNew(), BinderNode{binder,1}}); // FIXME: cleanup dedupe this 1 w/ ++ above
    LOG_ALWAYS_FATAL_IF(!it.second);  // FIXME: better organization could avoid needing this log

    *outAddress = it.first->first;
    return OK;
}

sp<IBinder> RpcState::onBinderEntering(const sp<RpcConnection>& connection, const RpcAddress& address) {
    LOG_ALWAYS_FATAL_IF(address == nullptr, "onBinderEntering null address");

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

    ALOGE("asdf insert lookup proxy first: %p", insert.first->first.get());

    // FIXME: might need to open up a new connection to this binder if it isn't
    // served directly from this connection, or this might be a binder object
    // which is held by another process.
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
              rwaToString(address).c_str(),
              desc);
    }
    ALOGE("END DUMP OF RpcState");
}

// FIXME: change way we are reading/writing from socket (bufferred? io_uring?
// recv_msg?)

static inline bool rpcSend(const base::unique_fd& fd, const char* what, const void* data, size_t size) {
    ALOGI("Sending %s on fd %d: %s", what, fd.get(), hexString(data, size).c_str());  // FIXME: spam

    // FIXME: range check (ssize_t)
    ssize_t sent = TEMP_FAILURE_RETRY(send(fd.get(), data, size, 0));
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
        ALOGI("Received %s on fd %d: %s", what, fd.get(), hexString(data, size).c_str());  // FIXME: spam
    }

    return true;
}

sp<IBinder> RpcState::getRootObject(const base::unique_fd& fd,
                                    const sp<RpcConnection>& connection) {
    Parcel data;
    data.markForRpc(connection);
    Parcel reply;

    status_t status = transact(fd, std::make_shared<RpcWireAddress>(),
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
    LOG_ALWAYS_FATAL_IF(address == nullptr, "Trying to transact with null address");

    if (!data.isForRpc()) {
        ALOGE("Refusing to send RPC with parcel not crafted for RPC");
        return BAD_TYPE;
    }

    if (data.objectsCount() != 0) {
        ALOGE("Parcel at %p has attached objects but is being used in an RPC call", &data);
        return BAD_TYPE;
    }

    RpcWireTransaction transaction {
        .address = *address,
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

    std::vector<uint8_t> replyData(command.bodySize);
    if (!rpcRec(fd, "reply body", replyData.data(), replyData.size())) {
        return NOT_ENOUGH_DATA;
    }
    // FIXME: check bodySize < sizeof(RpcWireReply)
    RpcWireReply* rpcReply = reinterpret_cast<RpcWireReply*>(replyData.data());

    if (rpcReply->status != OK) return rpcReply->status;

    // FIXME: use ipcSetDataReference, to avoid copy? or resize beforehand
    // instead of reading into std::vector, depends on how we optimize this.
    reply->setData(rpcReply->data, command.bodySize - offsetof(RpcWireReply, data));
    reply->markForRpc(connection);

    return OK;
}

status_t RpcState::sendDecStrong(const base::unique_fd& fd, const RpcAddress& addr) {
    {
        std::lock_guard<std::mutex> _l(mNodeMutex);
        auto it = mNodeForAddress.find(addr);
        LOG_ALWAYS_FATAL_IF(it == mNodeForAddress.end(), "Sending dec strong on unknown address %s", rwaToString(addr).c_str());
        LOG_ALWAYS_FATAL_IF(it->second.strong <= 0, "Bad dec strong %s", rwaToString(addr).c_str());

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
    if (!rpcSend(fd, "dec ref body", addr.get(), sizeof(RpcWireAddress))) return UNKNOWN_ERROR;
    return OK;
}

status_t RpcState::getAndExecuteCommand(const base::unique_fd& fd,
                                        const sp<RpcConnection>& connection) {
    ALOGE("getAndExecuteCommand in %d", getpid());

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
        return processDecRef(fd, command);
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
    // FIXME: heap allocation just for lookup
    auto addr = std::make_shared<RpcWireAddress>();
    memcpy(addr.get(), &transaction->address, sizeof(RpcWireAddress));

    sp<IBinder> target;

    RpcWireAddress ZERO{0};
    if (memcmp(addr.get(), &ZERO, sizeof(RpcWireAddress)) != 0) {
        std::lock_guard<std::mutex> _l(mNodeMutex);
        // FIXME: synchronization
        // FIXME: different lookup method?
        auto it = mNodeForAddress.find(addr);
        if (it == mNodeForAddress.end()) {
            ALOGE("Unknown binder address %s", rwaToString(transaction->address).c_str());
            dump();
            return UNKNOWN_ERROR;
        }
        // FIXME: assert this is a local binder (we aren't being asked to do a
        // command on a remote binder)
        target = it->second.binder.promote();
        if (target == nullptr) {
            ALOGE("Binder has been deleted at address %s", rwaToString(transaction->address).c_str()); // FIXME: combine with L248? or abstract lookup away
            // FIXME: add RpcWireHeader reply of type 'ERROR' so client can get a nicer
            // error?
            return UNKNOWN_ERROR;
        }
    }

    Parcel data;
    data.setData(transaction->data, command.bodySize - offsetof(RpcWireTransaction, data));

    data.markForRpc(connection);

    Parcel reply;
    // nullptr b/c we are only writing objects here, so they implicit come with
    // RpcConnection objects/addresses if they are needed.
    reply.markForRpc(connection);  // FIXME: connection needs renamed, comment updated

    status_t status;
    if (target) {
        status = target->transact(transaction->code, data, &reply, transaction->flags);
    } else {
        ALOGE("Got special transaction %u", transaction->code);
        // special case for 'zero' address (special server commands)
        // FIXME: make special transact read/writes adjacent to each other
        switch(transaction->code) {
            case RPC_SPECIAL_TRANSACT_GET_ROOT: {
                ALOGE("Writing root object %p", mRootObject.get());
                status = reply.writeStrongBinder(mRootObject);
                ALOGE("Write status: %s, reply size: %zu", statusToString(status).c_str(), reply.dataSize());
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

status_t RpcState::processDecRef(const base::unique_fd& fd,
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
    auto addr = std::make_shared<RpcWireAddress>();
    memcpy(addr.get(), address, sizeof(RpcWireAddress));

    std::unique_lock<std::mutex> _l(mNodeMutex);
    // FIXME: this is pasted from transact
    auto nit = mNodeForAddress.find(addr);
    if (nit == mNodeForAddress.end()) {
        ALOGE("Unknown binder address %s", rwaToString(*address).c_str());
        return UNKNOWN_ERROR;
    }

    sp<IBinder> target = nit->second.binder.promote();

    // FIXME: if this is a proxy, then one client might be sending extra dec
    // refs
    // We need to keep track of which processes we sent which proxies/things to

    if (target == nullptr) {
        ALOGE("Binder has been deleted at address %s", rwaToString(*address).c_str()); // FIXME: combine with L248? or abstract lookup away
        // FIXME: add RpcWireHeader reply of type 'ERROR' so client can get a nicer
        // error?
        return UNKNOWN_ERROR;
    }
    if (nit->second.strong == 0) {
        ALOGE("Binder does not have strong count at address %s", rwaToString(*address).c_str());
        // FIXME: add RpcWireHeader reply of type 'ERROR' so client can get a nicer
        // error?
        return UNKNOWN_ERROR;
    }

    // FIXME: range check, and also remove local entries (need to fix
    // RpcWireAddress ownership first)
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
