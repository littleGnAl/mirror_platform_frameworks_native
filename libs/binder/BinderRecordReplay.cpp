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

#include <android-base/logging.h>
#include <binder/BinderRecordReplay.h>

using android::Parcel;
using android::base::unique_fd;
using android::BinderRecordReplay::RecordedTransaction;

RecordedTransaction::RecordedTransaction() {
    mValid = false;
}

RecordedTransaction::RecordedTransaction(const unique_fd& fd) {
    readFromFile(fd);
}

RecordedTransaction::RecordedTransaction(uint32_t code, uint32_t flags, const Parcel& data,
                                         const Parcel& reply, status_t err) {
    fillTransaction(code, flags, data, reply, err);
}

bool RecordedTransaction::fillTransaction(uint32_t code, uint32_t flags, const Parcel& dataParcel,
                                          const Parcel& replyParcel, status_t err) {
    mValid = false;
    mSent.freeData();
    mReply.freeData();

    mHeader.code = code;
    mHeader.flags = flags;
    mHeader.dataSize = static_cast<uint64_t>(dataParcel.dataSize());
    mHeader.replySize = static_cast<uint64_t>(replyParcel.dataSize());
    mHeader.statusReturned = static_cast<int32_t>(err);
    mHeader.version = dataParcel.isForRpc() ? static_cast<uint32_t>(1) : static_cast<uint32_t>(0);

    if (mSent.setData(dataParcel.data(), getDataSize()) != android::NO_ERROR) {
        return false;
    }

    if (mReply.setData(replyParcel.data(), getReplySize()) != android::NO_ERROR) {
        return false;
    }

    return (mValid = true);
}

bool RecordedTransaction::readFromFile(const unique_fd& fd) {
    mValid = false;
    mSent.freeData();
    mReply.freeData();

    if (!android::base::ReadFully(fd, &mHeader, sizeof(mHeader))) {
        LOG(INFO) << "Failed to read transactionHeader from fd " << fd.get();
        return false;
    }

    uint8_t* bytes = (uint8_t*)malloc(getDataSize());
    if (bytes == nullptr || !android::base::ReadFully(fd, bytes, getDataSize())) {
        LOG(INFO) << "Failed to read sent parcel data from fd " << fd.get();
        return false;
    }
    mSent.setData(bytes, getDataSize());
    free(bytes);

    uint8_t padding[7];
    if (!android::base::ReadFully(fd, padding, (8 - getDataSize() % 8) % 8)) {
        LOG(INFO) << "Failed to read sent parcel padding from fd " << fd.get();
        return false;
    }

    bytes = (uint8_t*)malloc(getReplySize());
    if (bytes == nullptr || !android::base::ReadFully(fd, bytes, getReplySize())) {
        LOG(INFO) << "Failed to read reply parcel data from fd " << fd.get();
        return false;
    }
    mReply.setData(bytes, getReplySize());
    free(bytes);

    if (!android::base::ReadFully(fd, padding, (8 - getReplySize() % 8) % 8)) {
        LOG(INFO) << "Failed to read parcel padding from fd " << fd.get();
        return false;
    }

    return (mValid = true);
}

bool RecordedTransaction::dumpToFile(const unique_fd& fd) const {
    if (!isValid()) {
        return false;
    }
    if (!android::base::WriteFully(fd, &mHeader, sizeof(mHeader))) {
        LOG(INFO) << "Failed to write transactionHeader to fd " << fd.get();
        return false;
    }
    if (!android::base::WriteFully(fd, mSent.data(), getDataSize())) {
        LOG(INFO) << "Failed to write sent parcel data to fd " << fd.get();
        return false;
    }
    uint8_t zeros[8] = {0};
    if (!android::base::WriteFully(fd, zeros, ((8 - getDataSize() % 8) % 8))) {
        LOG(INFO) << "Failed to write sent parcel padding to fd " << fd.get();
        return false;
    }
    if (!android::base::WriteFully(fd, mReply.data(), getReplySize())) {
        LOG(INFO) << "Failed to write reply parcel data to fd " << fd.get();
        return false;
    }
    if (!android::base::WriteFully(fd, zeros, ((8 - getReplySize() % 8) % 8))) {
        LOG(INFO) << "Failed to write reply parcel padding to fd " << fd.get();
        return false;
    }
    return true;
}

bool RecordedTransaction::isValid() const {
    return mValid;
}

uint32_t RecordedTransaction::getCode() const {
    return mHeader.code;
}

uint32_t RecordedTransaction::getFlags() const {
    return mHeader.flags;
}

uint64_t RecordedTransaction::getDataSize() const {
    return mHeader.dataSize;
}

uint64_t RecordedTransaction::getReplySize() const {
    return mHeader.replySize;
}

int32_t RecordedTransaction::getReturnedStatus() const {
    return mHeader.statusReturned;
}

uint32_t RecordedTransaction::getVersion() const {
    return mHeader.version;
}

const Parcel& RecordedTransaction::getDataParcel() const {
    return mSent;
}

const Parcel& RecordedTransaction::getReplyParcel() const {
    return mReply;
}
