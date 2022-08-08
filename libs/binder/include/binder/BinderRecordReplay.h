/*
 * Copyright (C) 2022, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <android-base/file.h>
#include <binder/Parcel.h>
#include <mutex>

using android::base::unique_fd;

namespace android {

namespace BinderRecordReplay {

// Transactions are sequentially recorded to the file descriptor in the following format:
//
// RecordedTransaction.TransactionHeader  (32 bytes)
// Sent Parcel data                       (getDataSize() bytes)
// padding                                (enough bytes to align the reply Parcel data to 8 bytes)
// Reply Parcel data                      (getReplySize() bytes)
// padding                                (enough bytes to align the next header to 8 bytes)
// [repeats with next transaction]

class RecordedTransaction {
public:
    // Empty and thus not valid.
    RecordedTransaction();
    // Filled with the first transaction from fd.
    RecordedTransaction(const unique_fd& fd);
    // Filled with the arguments.
    RecordedTransaction(uint32_t code, uint32_t flags, const Parcel& data, const Parcel& reply,
                        status_t err);

    // Overwrite the current transaction with the passed information.
    bool fillTransaction(uint32_t code, uint32_t flags, const Parcel& data, const Parcel& reply,
                         status_t err);
    // Overwrite the current transaction with the first transaction in fd.
    bool readFromFile(const unique_fd& fd);

    // A transaction is valid if all of its fields were filled from a single
    // source, and no read/write errors occurred in the filling process.
    bool isValid() const;

    // The below functions should not be called if !isValid()
    bool dumpToFile(const unique_fd& fd) const;

    uint32_t getCode() const;
    uint32_t getFlags() const;
    uint64_t getDataSize() const;
    uint64_t getReplySize() const;
    int32_t getReturnedStatus() const;
    uint32_t getVersion() const;
    const Parcel& getDataParcel() const;
    const Parcel& getReplyParcel() const;

private:
    struct TransactionHeader {
        uint32_t code = 0;
        uint32_t flags = 0;
        uint64_t dataSize = 0;
        uint64_t replySize = 0;
        int32_t statusReturned = 0;
        uint32_t version = 0; // !0 iff Rpc
    };
    static_assert(sizeof(TransactionHeader) == 32);

    bool mValid;
    TransactionHeader mHeader;
    Parcel mSent;
    Parcel mReply;
};

} // namespace BinderRecordReplay

} // namespace android
