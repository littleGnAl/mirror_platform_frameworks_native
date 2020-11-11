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

status_t RpcState::transact(const base::unique_fd& fd, const RpcAddress* address, uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) {
    // FIXME: handle null address?

    RpcTransaction transaction {
        .address = address->address,
        .code = code,
        .flags = flags,  // FIXME prune
    };

    // FIXME: save extra copy? with real scatter-gather? :)
    std::vector<uint8_t> transactionData(sizeof(RpcTransaction) + data.dataSize());
    memcpy(transactionData.data() + 0, &transaction, sizeof(RpcTransaction));
    memcpy(transactionData.data() + sizeof(RpcTransaction), data.data(), data.dataSize());

    RpcCommand command {
        .command = RPC_COMMAND_TRANSACT,
        .bodySize = (uint32_t) transactionData.size(), // FIXME: range check
    };

    if (sizeof(RpcCommand) != TEMP_FAILURE_RETRY(send(fd.get(), &command, sizeof(command), 0))) {
        ALOGE("Failed to send command header: %s", strerror(errno));
        return UNKNOWN_ERROR;
    }

    // FIXME: bad cast
    if ((int)transactionData.size() != TEMP_FAILURE_RETRY(send(fd.get(), transactionData.data(), transactionData.size(), 0))) {
        ALOGE("Failed to send command body: %s", strerror(errno));
        return UNKNOWN_ERROR;
    }

    ALOGE("FIXME: need to read reply");

    // FIXME: wait for reply
    (void) reply;

    return OK;
}

status_t RpcState::getAndExecuteCommand(const base::unique_fd& fd) {
    ALOGE("PROCESSING COMMAND in %d", getpid());

    // FIXME: what's the best way to read from a socket?
    // FIXME: switch to using Parcel to parse the data from the kernel, like
    // IPCThreadState does?
    // FIXME: clean this all up....

    RpcCommand command;
    // FIXME: error handling/synchronization?
    // FIXME: detect incomplete read
    if (0 == TEMP_FAILURE_RETRY(recv(fd.get(), &command, sizeof(command), MSG_WAITALL))) {
        if (errno == 0) {
            return NOT_ENOUGH_DATA; // FIXME
        }
        ALOGE("Error reading rpc command header: %s", strerror(errno));

        return UNKNOWN_ERROR;
    }

    LOG_ALWAYS_FATAL_IF(command.command != RPC_COMMAND_TRANSACT);
    // FIXME: avoid allocating extra size here?
    std::vector<uint8_t> transactionData(command.bodySize);
    // FIXME: detect incomplete read
    if (0 == TEMP_FAILURE_RETRY(recv(fd.get(), transactionData.data(), transactionData.size(), MSG_WAITALL))) {
        if (errno == 0) {
            return NOT_ENOUGH_DATA; // FIXME
        }
        ALOGE("Error reading rpc command body: %s", strerror(errno));
        return UNKNOWN_ERROR;
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
    return it->second->transact(transaction->code, data, &reply, transaction->flags);

    // FIXME: send respones
}

status_t RpcState::waitForReply(const base::unique_fd& fd, Parcel* reply) {
    (void) fd;
    (void) reply;
    return OK;
}

} // namespace android
