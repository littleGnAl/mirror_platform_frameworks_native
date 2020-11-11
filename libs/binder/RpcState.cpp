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

#include "RpcCommands.h"

namespace android {

void RpcState::attachBinder(const sp<IBinder>& binder) {
    RpcAddress address = RpcAddress{(int)mBinders.size()};
    mBinders[address] = binder;
}

// FIXME: write now, we are using this primitive too much, should switch to
// recvmsg, scatter gather, and also potentially buffering calls here if we are
// sending too many at once

static inline bool rpcSend(const base::unique_fd& fd, const char* what, void* data, size_t size) {
    ssize_t sent = TEMP_FAILURE_RETRY(send(fd.get(), data, size, 0));

    // FIXME: range check size
    if (sent != (ssize_t) size) {
        ALOGE("Failed to send %s (sent %zd of %zu bytes), error: %s",
              what, sent, size, strerror(errno));
        return false;
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
    }

    return true;
}

status_t RpcState::transact(const base::unique_fd& fd, const RpcAddress* address, uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) {
    // FIXME: handle null address?
    // FIXME: send w/o such a mess, w/o copies, scatter-gather
    // FIXME: check that parcel does not have any objects

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

    return waitForReply(fd, reply);
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

    Parcel reply;
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

status_t RpcState::waitForReply(const base::unique_fd& fd, Parcel* reply) {
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

    return OK;
}

} // namespace android
