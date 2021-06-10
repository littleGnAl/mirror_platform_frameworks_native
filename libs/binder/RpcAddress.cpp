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

#include <binder/RpcAddress.h>

#include <binder/Parcel.h>

#include "Debug.h"
#include "RpcState.h"
#include "RpcWireFormat.h"

namespace android {

RpcAddress RpcAddress::zero() {
    return RpcAddress();
}

bool RpcAddress::isZero() const {
    RpcWireAddress ZERO{0};
    return memcmp(mRawAddr.get(), &ZERO, sizeof(RpcWireAddress)) == 0;
}

static void ReadRandomBytes(uint8_t* buf, size_t len) {
    int fd = TEMP_FAILURE_RETRY(open("/dev/urandom", O_RDONLY | O_CLOEXEC | O_NOFOLLOW));
    if (fd == -1) {
        ALOGE("%s: cannot read /dev/urandom", __func__);
        return;
    }

    size_t n;
    while ((n = TEMP_FAILURE_RETRY(read(fd, buf, len))) > 0) {
        len -= n;
        buf += n;
    }
    if (len > 0) {
        ALOGW("%s: there are %d bytes skipped", __func__, (int)len);
    }
    close(fd);
}

constexpr size_t kHeaderFlagForServer = 1;

RpcAddress RpcAddress::unique(bool forServer) {
    // The remainder of this header acts as reserved space for different kinds
    // of binder objects.
    uint64_t header = 0;

    // servers and clients allocate addresses independently, so this bit can
    // tell you where an address originates
    if (forServer) header |= kHeaderFlagForServer;

    RpcAddress ret;
    uint8_t* raw = reinterpret_cast<uint8_t*>(ret.mRawAddr.get());

    static_assert(sizeof(RpcWireAddress) > sizeof(header));
    memcpy(raw, &header, sizeof(header));
    ReadRandomBytes(raw + sizeof(header), sizeof(RpcWireAddress) - sizeof(header));

    LOG_RPC_DETAIL("Creating new address: %s", ret.toString().c_str());
    return ret;
}

bool RpcAddress::isForServer() const {
    uint64_t header = *reinterpret_cast<uint64_t*>(mRawAddr.get());
    return header & kHeaderFlagForServer;
}

bool RpcAddress::isRecognizedType() const {
    uint64_t header = *reinterpret_cast<uint64_t*>(mRawAddr.get());
    return (header & (~kHeaderFlagForServer)) == 0;
}

RpcAddress RpcAddress::fromRawEmbedded(const RpcWireAddress* raw) {
    RpcAddress addr;
    memcpy(addr.mRawAddr.get(), raw, sizeof(RpcWireAddress));
    return addr;
}

const RpcWireAddress& RpcAddress::viewRawEmbedded() const {
    return *mRawAddr.get();
}

bool RpcAddress::operator<(const RpcAddress& rhs) const {
    return std::memcmp(mRawAddr.get(), rhs.mRawAddr.get(), sizeof(RpcWireAddress)) < 0;
}

std::string RpcAddress::toString() const {
    return hexString(mRawAddr.get(), sizeof(RpcWireAddress));
}

status_t RpcAddress::writeToParcel(Parcel* parcel) const {
    return parcel->write(mRawAddr.get(), sizeof(RpcWireAddress));
}

status_t RpcAddress::readFromParcel(const Parcel& parcel) {
    return parcel.read(mRawAddr.get(), sizeof(RpcWireAddress));
}

RpcAddress::~RpcAddress() {}
RpcAddress::RpcAddress() : mRawAddr(std::make_shared<RpcWireAddress>()) {}

} // namespace android
