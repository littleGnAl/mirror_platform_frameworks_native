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

#include <android-base/hex.h>
#include <binder/Parcel.h>

#include "Debug.h"
#include "RpcState.h"
#include "RpcWireFormat.h"

#include <atomic>

namespace android {

RpcAddress RpcAddress::zero() {
    return RpcAddress();
}

bool RpcAddress::isZero() const {
    RpcWireAddress ZERO{.options = 0};
    return memcmp(mRawAddr.get(), &ZERO, sizeof(RpcWireAddress)) == 0;
}

RpcAddress RpcAddress::random(bool forServer) {
    // The remainder of this header acts as reserved space for different kinds
    // of binder objects.
    uint64_t options = RPC_WIRE_ADDRESS_OPTION_CREATED;

    // servers and clients allocate addresses independently, so this bit can
    // tell you where an address originates
    if (forServer) options |= RPC_WIRE_ADDRESS_OPTION_FOR_SERVER;

    RpcAddress ret;
    RpcWireAddress* raw = ret.mRawAddr.get();

    // FIXME: this is not okay for RpcSession IDs which shouldn't be guessable.
    // and this is a hack. If we really want to change this, we should keep
    // RpcSession as a large unguessable ID and change the binder ID to be fewer
    // bits.

    raw->options = options;

    static std::atomic<uint64_t> i = 0;
    static_assert(sizeof(raw->address) > sizeof(i));
    *((uint64_t*)raw->address) = i++;

    LOG_RPC_DETAIL("Creating new address: %s", ret.toString().c_str());
    return ret;
}

bool RpcAddress::isForServer() const {
    return mRawAddr.get()->options & RPC_WIRE_ADDRESS_OPTION_FOR_SERVER;
}

bool RpcAddress::isRecognizedType() const {
    uint64_t allKnownOptions = RPC_WIRE_ADDRESS_OPTION_CREATED | RPC_WIRE_ADDRESS_OPTION_FOR_SERVER;
    return (mRawAddr.get()->options & ~allKnownOptions) == 0;
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
    return base::HexString(mRawAddr.get(), sizeof(RpcWireAddress));
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
