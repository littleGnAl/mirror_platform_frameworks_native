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

#include <binder/RpcState.h>

#include <binder/BpBinder.h>

#include "RpcCommands.h"

namespace android {

RpcState& RpcState::self() {
    static RpcState state;
    return state;
}

sp<IBinder> RpcState::getOrLookupProxy(const sp<RpcConnection>& connection, RpcAddress&& address) {
    auto it = mBinders.find(address);
    if (it != mBinders.end()) {
        return it->second;
    }

    auto insert = mBinders.insert({address, nullptr});
    LOG_ALWAYS_FATAL_IF(!insert.second, "Failed to insert binder");

    // FIXME: might need to open up a new connection to this binder if it isn't
    // served directly from this connection
    sp<IBinder> binder = BpBinder::create(connection, &insert.first->first);
    insert.first->second = binder;
    return binder;
}

const RpcAddress* RpcState::attachBinder(const sp<IBinder>& binder) {
    // FIXME: how to handle attaching BpBinder
    // - disallow (leaning)
    // - allow connection through current process
    // FIXME: seriously, this is trash
    bool isRpc = binder->remoteBinder() && binder->remoteBinder()->isRpcBinder();
    // FIXME: avoid O(n) lookup. By storing addresses inside of BBinder as well???
    for (const auto& [addr, knownBinder] : mBinders) {
        if (binder == knownBinder) {
            if (isRpc) {
                // Avoid duplicated data structures, either we should store
                // the address in binder objects or we should have a way to look
                // it up quickly elsewhere. This check is to test assumptions,
                // but it would be trivial to change this data structure to
                // avoid those assumptions. FIXME
                LOG_ALWAYS_FATAL_IF(&addr != binder->remoteBinder()->address());
            }
            return &addr;
        }
    }
    LOG_ALWAYS_FATAL_IF(isRpc, "RPC binder must have known address at this point");
    // FIXME: don't copy address here
    RpcAddress address = RpcAddress{(int)mBinders.size()};
    auto it = mBinders.insert({address, binder});
    LOG_ALWAYS_FATAL_IF(!it.second, "Failed to insert binder");
    return &it.first->first;
}

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

// FIXME: write now, we are using this primitive too much, should switch to
// recvmsg, scatter gather, and also potentially buffering calls here if we are
// sending too many at once

static inline bool rpcSend(const base::unique_fd& fd, const char* what, void* data, size_t size) {
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
                            const RpcAddress* address,
                            uint32_t code,
                            const Parcel& data,
                            Parcel* reply,
                            uint32_t flags) {
    // FIXME: handle null address?
    // FIXME: send w/o such a mess, w/o copies, scatter-gather
    // FIXME: check that parcel is written for RPC calls (entire format)
    if (data.objectsCount() != 0) {
        ALOGE("Parcel at %p has attached objects but is being used in an RPC call", &data);
        return BAD_TYPE;
    }

    RpcTransaction transaction {
        .address = address->address,
        .code = code,
        .flags = flags,  // FIXME prune
    };

    std::vector<uint8_t> transactionData(sizeof(RpcTransaction) + data.dataSize());
    memcpy(transactionData.data() + 0, &transaction, sizeof(RpcTransaction));
    memcpy(transactionData.data() + sizeof(RpcTransaction), data.data(), data.dataSize());

    RpcCommand command {
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
    RpcCommand command;
    if (!rpcRec(fd, "command header", &command, sizeof(command))) {
        return NOT_ENOUGH_DATA;
    }

    // FIXME: support nested commands
    LOG_ALWAYS_FATAL_IF(command.command != RPC_COMMAND_REPLY);

    std::vector<uint8_t> replyData(command.bodySize);
    if (!rpcRec(fd, "reply body", replyData.data(), replyData.size())) {
        return NOT_ENOUGH_DATA;
    }
    // FIXME: check bodySize < sizeof(RpcReply)
    RpcReply* rpcReply = reinterpret_cast<RpcReply*>(replyData.data());

    if (rpcReply->status != OK) return rpcReply->status;

    // FIXME: use ipcSetDataReference, to avoid copy? or resize beforehand
    // instead of reading into std::vector, depends on how we optimize this.
    reply->setData(rpcReply->data, command.bodySize - offsetof(RpcReply, data));
    reply->markForRpc(connection);

    return OK;
}

status_t RpcState::getAndExecuteCommand(const base::unique_fd& fd) {
    ALOGE("PROCESSING COMMAND in %d", getpid());

    // FIXME: what's the best way to read from a socket?
    // FIXME: switch to using Parcel to parse the data from the kernel, like
    // IPCThreadState does?
    // FIXME: clean this all up....

    RpcCommand command;
    if (!rpcRec(fd, "command header", &command, sizeof(command))) {
        return NOT_ENOUGH_DATA;
    }

    // FIXME: error handling
    LOG_ALWAYS_FATAL_IF(command.command != RPC_COMMAND_TRANSACT);

    // FIXME: avoid allocating extra size here?
    std::vector<uint8_t> transactionData(command.bodySize);
    if (!rpcRec(fd, "transaction body", transactionData.data(), transactionData.size())) {
        return NOT_ENOUGH_DATA;
    }

    // FIXME: check bodySize < sizeof(RpcTransaction)
    RpcTransaction* transaction = reinterpret_cast<RpcTransaction*>(transactionData.data());
    // FIXME: synchronization
    // FIXME: different lookup method?
    auto it = mBinders.find(RpcAddress{transaction->address});
    if (it == mBinders.end()) {
        ALOGE("Unknown binder address %d", transaction->address);
        return UNKNOWN_ERROR;
    }

    Parcel data;
    data.setData(transaction->data, command.bodySize - offsetof(RpcTransaction, data));

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
    status_t status = it->second->transact(transaction->code, data, &reply, transaction->flags);

    if (transaction->flags & IBinder::FLAG_ONEWAY) {
        if (status != OK) {
            ALOGW("Oneway call failed with error: %d", status);
        }
        return OK;
    }

    RpcReply rpcReply {
        .status = status,
    };

    std::vector<uint8_t> replyData(sizeof(RpcReply) + data.dataSize());
    memcpy(replyData.data() + 0, &rpcReply, sizeof(RpcReply));
    memcpy(replyData.data() + sizeof(RpcReply), reply.data(), reply.dataSize());

    RpcCommand cmdReply {
        .command = RPC_COMMAND_REPLY,
        .bodySize = (uint32_t) replyData.size(), // FIXME: range check
    };

    if (!rpcSend(fd, "reply header", &cmdReply, sizeof(RpcCommand))) {
        return UNKNOWN_ERROR;
    }
    if (!rpcSend(fd, "reply body", replyData.data(), replyData.size())) {
        return UNKNOWN_ERROR;
    }
    return OK;
}

} // namespace android
