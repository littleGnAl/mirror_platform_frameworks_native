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
bool operator< (const RpcWireAddress& lhs, const RpcWireAddress& rhs) {
    return std::memcmp(&lhs, &rhs, sizeof(RpcWireAddress)) < 0;
}
std::string rwaToString(const RpcWireAddress& rwa) {
    return hexString(&rwa, sizeof(rwa));
}
RpcWireAddress rwaNew() {
    // FIXME: use cryptographically secure way to make these or otherwise
    // delegate to a centralized server
    static bool hackOnce = [](){srand(getpid() + time(0)); return true;}();
    (void) hackOnce;
    RpcWireAddress addr {};
    for (size_t i = 0; i < sizeof(addr.address); i++) {
        addr.address[i] = (uint8_t)rand();
    }
    ALOGE("Creating new address: %s", rwaToString(addr).c_str());
    return addr;
}

// FIXME: END RPC ADDRESS STUFF

RpcState& RpcState::self() {
    static RpcState state;
    return state;
}

void RpcState::setRootObject(const sp<IBinder>& binder) {
    // FIXME: RpcState should own lifetime of this object, not RpcServer?
    auto insert = mNodeForAddress.insert({RpcWireAddress{0}, BinderNode{binder, 0}});
    LOG_ALWAYS_FATAL_IF(!insert.second, "Can only set root binder once");
}

sp<IBinder> RpcState::lookupOrCreateProxy(const sp<RpcConnection>& connection, RpcWireAddress&& address) {
    auto it = mNodeForAddress.find(address);
    if (it != mNodeForAddress.end()) {
        return it->second.binder.promote();
    }

    auto insert = mNodeForAddress.insert({address, BinderNode{}});
    LOG_ALWAYS_FATAL_IF(!insert.second, "Failed to insert binder when creating proxy");

    // FIXME: might need to open up a new connection to this binder if it isn't
    // served directly from this connection
    sp<IBinder> binder = BpBinder::create(connection, &insert.first->first);
    insert.first->second.binder = binder;
    insert.first->second.strong = 0;
    return binder;
}

void RpcState::dump() {
    ALOGE("DUMP OF RpcState");
    for (const auto& [address, node] : mNodeForAddress) {
        ALOGE("- BINDER NODE: %p s:%zu a:%s", node.binder.unsafe_get(), node.strong, rwaToString(address).c_str());
    }
}

const RpcWireAddress* RpcState::attachBinder(const sp<IBinder>& binder) {
    // FIXME: this should be next to incs of node.strong on other lines
    binder->incStrong(nullptr);

    // FIXME: how to handle attaching BpBinder
    // - disallow (leaning)
    // - allow connection through current process
    // FIXME: seriously, this is trash
    bool isRpc = binder->remoteBinder() && binder->remoteBinder()->isRpcBinder();
    // FIXME: avoid O(n) lookup. By storing addresses inside of BBinder as well???
    for (auto& [addr, node] : mNodeForAddress) {
        if (binder == node.binder) {
            if (isRpc) {
                // Avoid duplicated data structures, either we should store
                // the address in binder objects or we should have a way to look
                // it up quickly elsewhere. This check is to test assumptions,
                // but it would be trivial to change this data structure to
                // avoid those assumptions. FIXME
                LOG_ALWAYS_FATAL_IF(&addr != binder->remoteBinder()->address(), "Address mismatch");
            }
            node.strong++;
            return &addr;
        }
    }
    LOG_ALWAYS_FATAL_IF(isRpc, "RPC binder must have known address at this point");
    // FIXME: don't copy address here
    RpcWireAddress addr = rwaNew();
    auto it = mNodeForAddress.insert({addr, BinderNode{binder,1}}); // FIXME: cleanup dedupe this 1 w/ ++ above
    if (!it.second) dump(); // FIXME
    LOG_ALWAYS_FATAL_IF(!it.second, "Failed to insert binder in attachBinder: %s %p", rwaToString(addr).c_str(), binder.get());
    return &it.first->first;
}

// FIXME: right now, we are using this primitive too much, should switch to
// recvmsg, scatter gather, and also potentially buffering calls here if we are
// sending too many at once

static inline bool rpcSend(const base::unique_fd& fd, const char* what, const void* data, size_t size) {
    ALOGI("About to send %s: %s", what, hexString(data, size).c_str());  // FIXME: spam

    ssize_t sent = TEMP_FAILURE_RETRY(send(fd.get(), data, size, 0));

    // FIXME: range check size
    if (sent != (ssize_t) size) {
        ALOGE("Failed to send %s (sent %zd of %zu bytes), error: %s",
              what, sent, size, strerror(errno));
        return false;
    } else {
        ALOGI("Send successful");
    }

    return true;
}

static inline bool rpcRec(const base::unique_fd& fd, const char* what, void* data, size_t size) {

    ssize_t recd = TEMP_FAILURE_RETRY(recv(fd.get(), data, size, MSG_WAITALL));

    // FIXME: range check this
    if (recd != (ssize_t) size) {
        ALOGE("Failed to read %s (received %zd of %zu bytes), error: %s",
              what, recd, size, strerror(errno));
        return false;
    } else {
        ALOGI("Received %s: %s", what, hexString(data, size).c_str());  // FIXME: spam
    }

    return true;
}

status_t RpcState::transact(const base::unique_fd& fd,
                            const RpcWireAddress* address,
                            uint32_t code,
                            const Parcel& data,
                            const sp<RpcConnection>& replyConnection,
                            Parcel* reply,
                            uint32_t flags) {
    if (!data.isForRpc()) {
        ALOGE("Refusing to send RPC with parcel not crafted for RPC");
        return BAD_TYPE;
    }
    // FIXME: handle null address?
    // FIXME: send w/o such a mess, w/o copies, scatter-gather
    // FIXME: check that parcel is written for RPC calls (entire format)
    if (data.objectsCount() != 0) {
        ALOGE("Parcel at %p has attached objects but is being used in an RPC call", &data);
        return BAD_TYPE;
    }

    RpcWireTransaction transaction {
        .address = *address,
        .code = code,
        .flags = flags,  // FIXME prune
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

    // FIXME: handle fake reply parcelable, like libbinder does, or fix callers?
    LOG_ALWAYS_FATAL_IF(reply == nullptr, "NO!");

    if (flags & IBinder::FLAG_ONEWAY) {
        return OK;  // do not wait for result
    }

    return waitForReply(fd, replyConnection, reply);
}

status_t RpcState::waitForReply(const base::unique_fd& fd,
                                const sp<RpcConnection>& replyConnection,
                                Parcel* reply) {
    RpcWireHeader command;
    while (true) {
        if (!rpcRec(fd, "command header", &command, sizeof(command))) {
            return NOT_ENOUGH_DATA;
        }

        if (command.command == RPC_COMMAND_REPLY) break;

        status_t status = processServerCommand(fd, replyConnection, command);
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
    reply->markForRpc(replyConnection);

    return OK;
}

status_t RpcState::sendDecStrong(const base::unique_fd& fd, const RpcWireAddress* addr) {
    RpcWireHeader cmd = {
        .command = RPC_COMMAND_DEC_STRONG,
        .bodySize = sizeof(RpcWireAddress),
    };
    if (!rpcSend(fd, "dec ref header", &cmd, sizeof(cmd))) return UNKNOWN_ERROR;
    if (!rpcSend(fd, "dec ref body", addr, sizeof(*addr))) return UNKNOWN_ERROR;
    return OK;
}

status_t RpcState::getAndExecuteCommand(const base::unique_fd& fd,
                                        const sp<RpcConnection>& replyConnection) {
    ALOGE("PROCESSING COMMAND in %d", getpid());

    // FIXME: what's the best way to read from a socket?
    // FIXME: switch to using Parcel to parse the data from the kernel, like
    // IPCThreadState does?
    // FIXME: clean this all up....

    RpcWireHeader command;
    if (!rpcRec(fd, "command header", &command, sizeof(command))) {
        return NOT_ENOUGH_DATA;
    }

    return processServerCommand(fd, replyConnection, command);
}

status_t RpcState::processServerCommand(const base::unique_fd& fd,
                                        const sp<RpcConnection>& replyConnection,
                                        const RpcWireHeader& command) {
    switch (command.command) {
    case RPC_COMMAND_TRANSACT:
        return processTransact(fd, replyConnection, command);
    case RPC_COMMAND_DEC_STRONG:
        return processDecRef(fd, command);
    }
    ALOGE("Unknown RPC command %d", command.command);
    return UNKNOWN_ERROR;
}
status_t RpcState::processTransact(const base::unique_fd& fd,
                                   const sp<RpcConnection>& replyConnection,
                                   const RpcWireHeader& command) {
    LOG_ALWAYS_FATAL_IF(command.command != RPC_COMMAND_TRANSACT, "command: %d", command.command);

    // FIXME: avoid allocating extra size here?
    std::vector<uint8_t> transactionData(command.bodySize);
    if (!rpcRec(fd, "transaction body", transactionData.data(), transactionData.size())) {
        return NOT_ENOUGH_DATA;
    }

    // FIXME: check bodySize < sizeof(RpcWireTransaction)
    RpcWireTransaction* transaction = reinterpret_cast<RpcWireTransaction*>(transactionData.data());
    // FIXME: synchronization
    // FIXME: different lookup method?
    auto it = mNodeForAddress.find(transaction->address);
    if (it == mNodeForAddress.end()) {
        ALOGE("Unknown binder address %s", rwaToString(transaction->address).c_str());
        dump();
        return UNKNOWN_ERROR;
    }
    // FIXME: assert this is a local binder (we aren't being asked to do a
    // command on a remote binder)
    sp<IBinder> target = it->second.binder.promote();
    if (target == nullptr) {
        ALOGE("Binder has been deleted at address %s", rwaToString(transaction->address).c_str()); // FIXME: combine with L248? or abstract lookup away
        // FIXME: add RpcWireHeader reply of type 'ERROR' so client can get a nicer
        // error?
        return UNKNOWN_ERROR;
    }

    Parcel data;
    data.setData(transaction->data, command.bodySize - offsetof(RpcWireTransaction, data));

    data.markForRpc(replyConnection);

    Parcel reply;
    // nullptr b/c we are only writing objects here, so they implicit come with
    // RpcConnection objects/addresses if they are needed.
    reply.markForRpc(nullptr);
    status_t status = target->transact(transaction->code, data, &reply, transaction->flags);

    if (transaction->flags & IBinder::FLAG_ONEWAY) {
        if (status != OK) {
            ALOGW("Oneway call failed with error: %d", status);
        }
        return OK;
    }

    RpcWireReply rpcReply {
        .status = status,
    };

    std::vector<uint8_t> replyData(sizeof(RpcWireReply) + data.dataSize());
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

    // FIXME: this is pasted from transact
    auto nit = mNodeForAddress.find(*address);
    if (nit == mNodeForAddress.end()) {
        ALOGE("Unknown binder address %s", rwaToString(*address).c_str());
        return UNKNOWN_ERROR;
    }

    // FIXME: avoid special case
    RpcWireAddress ZERO{0};
    if (memcmp(address, &ZERO, sizeof(RpcWireAddress)) == 0) {
        // FIXME: hack, consider avoid sending in the first place, or
        // require clients to pass their ownership information of this w/
        // special transactions (e.g. RPC_COMMAND_GET_ROOT)
        // FIXME: either way, this needs a test when the root object sends
        // itself out
        return OK;
    }

    // FIXME: assert this is a local binder (we aren't being asked to do a
    // command on a remote binder)
    sp<IBinder> target = nit->second.binder.promote();
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
    target->decStrong(nullptr);
    return OK;
}

} // namespace android
