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
    auto insert = mBinderForAddress.insert({RpcWireAddress{0}, binder});
    LOG_ALWAYS_FATAL_IF(!insert.second, "Can only set root binder once");
}

sp<IBinder> RpcState::lookupOrCreateProxy(const sp<RpcConnection>& connection, RpcWireAddress&& address) {
    auto it = mBinderForAddress.find(address);
    if (it != mBinderForAddress.end()) {
        return it->second.promote();
    }

    auto insert = mBinderForAddress.insert({address, nullptr});
    LOG_ALWAYS_FATAL_IF(!insert.second, "Failed to insert binder when creating proxy");

    // FIXME: might need to open up a new connection to this binder if it isn't
    // served directly from this connection
    sp<IBinder> binder = BpBinder::create(connection, &insert.first->first);
    insert.first->second = binder;
    return binder;
}

void RpcState::dump() {
    ALOGE("DUMP OF RPCSTATE");
    for (const auto& [address, binder] : mBinderForAddress) {
        ALOGE("- KNOWN ADDRESS: %p %s", binder.unsafe_get(), rwaToString(address).c_str());
    }
    for (const sp<IBinder>& ref : mExternalStrongRefs) {
        ALOGE("- EXTERNAL REF FOR: %p", ref.get());
    }

}

const RpcWireAddress* RpcState::attachBinder(const sp<IBinder>& binder) {
    // FIXME: optimize
    mExternalStrongRefs.push_back(binder);

    // FIXME: how to handle attaching BpBinder
    // - disallow (leaning)
    // - allow connection through current process
    // FIXME: seriously, this is trash
    bool isRpc = binder->remoteBinder() && binder->remoteBinder()->isRpcBinder();
    // FIXME: avoid O(n) lookup. By storing addresses inside of BBinder as well???
    for (const auto& [addr, knownBinder] : mBinderForAddress) {
        if (binder == knownBinder) {
            if (isRpc) {
                // Avoid duplicated data structures, either we should store
                // the address in binder objects or we should have a way to look
                // it up quickly elsewhere. This check is to test assumptions,
                // but it would be trivial to change this data structure to
                // avoid those assumptions. FIXME
                LOG_ALWAYS_FATAL_IF(&addr != binder->remoteBinder()->address(), "Address mismatch");
            }
            return &addr;
        }
    }
    LOG_ALWAYS_FATAL_IF(isRpc, "RPC binder must have known address at this point");
    // FIXME: don't copy address here
    RpcWireAddress addr = rwaNew();
    auto it = mBinderForAddress.insert({addr, binder});
    dump();
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

status_t RpcState::transact(const sp<RpcConnection>& connection,
                            const base::unique_fd& fd,
                            const RpcWireAddress* address,
                            uint32_t code,
                            const Parcel& data,
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

    return waitForReply(connection, fd, reply);
}

status_t RpcState::waitForReply(const sp<RpcConnection>& connection,
                                const base::unique_fd& fd,
                                Parcel* reply) {
    RpcWireHeader command;
    while (true) {
        if (!rpcRec(fd, "command header", &command, sizeof(command))) {
            return NOT_ENOUGH_DATA;
        }

        if (command.command == RPC_COMMAND_REPLY) break;

        // we might serve responses from who we are talking to if it calls back
        // into us before we get a reply.
        //
        // FIXME: this is another difference with a regular binder threadpool.
        // If we are process A, and we call process B which calls process C,
        // which calls back into us, process C has no way to connect and process
        // a command on this thread, so we must have another thread
        // available/started with process C elsewhere.
        status_t status = processServerCommand(fd, command);
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

status_t RpcState::sendDecStrong(const base::unique_fd& fd, const RpcWireAddress* addr) {
    RpcWireHeader cmd = {
        .command = RPC_COMMAND_DEC_STRONG,
        .bodySize = sizeof(RpcWireAddress),
    };
    if (!rpcSend(fd, "dec ref header", &cmd, sizeof(cmd))) return UNKNOWN_ERROR;
    if (!rpcSend(fd, "dec ref body", addr, sizeof(*addr))) return UNKNOWN_ERROR;
    return OK;
}

status_t RpcState::getAndExecuteCommand(const base::unique_fd& fd) {
    ALOGE("PROCESSING COMMAND in %d", getpid());

    // FIXME: what's the best way to read from a socket?
    // FIXME: switch to using Parcel to parse the data from the kernel, like
    // IPCThreadState does?
    // FIXME: clean this all up....

    RpcWireHeader command;
    if (!rpcRec(fd, "command header", &command, sizeof(command))) {
        return NOT_ENOUGH_DATA;
    }

    return processServerCommand(fd, command);
}

status_t RpcState::processServerCommand(const base::unique_fd& fd,
                                        const RpcWireHeader& command) {
    switch (command.command) {
    case RPC_COMMAND_TRANSACT:
        return processTransact(fd, command);
    case RPC_COMMAND_DEC_STRONG:
        return processDecRef(fd, command);
    }
    ALOGE("Unknown RPC command %d", command.command);
    return UNKNOWN_ERROR;
}
status_t RpcState::processTransact(const base::unique_fd& fd,
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
    auto it = mBinderForAddress.find(transaction->address);
    if (it == mBinderForAddress.end()) {
        ALOGE("Unknown binder address %s", rwaToString(transaction->address).c_str());
        dump();
        return UNKNOWN_ERROR;
    }
    sp<IBinder> target = it->second.promote();
    if (target == nullptr) {
        ALOGE("Binder has been deleted at address %s", rwaToString(transaction->address).c_str()); // FIXME: combine with L248? or abstract lookup away
        // FIXME: add RpcWireHeader reply of type 'ERROR' so client can get a nicer
        // error?
        return UNKNOWN_ERROR;
    }

    Parcel data;
    data.setData(transaction->data, command.bodySize - offsetof(RpcWireTransaction, data));

    // FIXME: this is a change in the threading pool model
    // This connection represent a single thread which can serve requests as a
    // response to a thread, so for instance, if we have:
    //
    //     PROC A                PROC B
    //    BINDER 1              BINDER 2
    //    BINDER 3
    //       -------sendBinder--->
    //              to BINDER 2
    //              w/ BINDER 3
    //                          BINDER 3 (ref)
    //
    // In this scenario BINDER 3, since it is read from this data parcel, will
    // inherit this connection, and if PROC B makes a call on BINDER 3, then it
    // will only have a single thread to process it on.
    //
    // This comes with a restriction in one case:
    // PROC B needs to make many calls to BINDER 3
    //
    // In this case, we would actualy like to inherit some larger connection to
    // PROC A, either by creating it, or by adopting it by looking up a
    // reference to A.
    //
    // Solutions:
    // - switch connection/server to be a global object per-process
    // - add a function to BpBinder which allows you to create a custom larger
    //   connection for the single binder
    // - ???
    sp<RpcConnection> replyConnection = RpcConnection::responseConnection(fd);
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
    auto bit = mBinderForAddress.find(*address);
    if (bit == mBinderForAddress.end()) {
        ALOGE("Unknown binder address %s", rwaToString(*address).c_str());
        return UNKNOWN_ERROR;
    }
    sp<IBinder> target = bit->second.promote();
    if (target == nullptr) {
        ALOGE("Binder has been deleted at address %s", rwaToString(*address).c_str()); // FIXME: combine with L248? or abstract lookup away
        // FIXME: add RpcWireHeader reply of type 'ERROR' so client can get a nicer
        // error?
        return UNKNOWN_ERROR;
    }

    auto rit = std::find(mExternalStrongRefs.begin(), mExternalStrongRefs.end(), target);
    if (rit == mExternalStrongRefs.end()) {
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
        ALOGE("Requested dec ref for binder, but we have no record it is owned: %s", rwaToString(*address).c_str());
        return UNKNOWN_ERROR;
    }
    mExternalStrongRefs.erase(rit);
    return OK;
}

} // namespace android
