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
#pragma once

#include <utils/RefBase.h>
#include <utils/Errors.h>

namespace android {

class Parcel;

// FIXME: actually support this setup, instead of just one.
// This represents a connection to a set of sockets.
class RpcConnection : public RefBase {
public:
    // FIXME: what's the best way to expose these APIs? One per-type?
    // FIXME: get connection setup from context manager
    static sp<RpcConnection> connect(const char* path);

    // FIXME: add methods to modify thread counts
    // bool requestAddThread(); ???

    status_t transact(int address, uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags);

    ~RpcConnection();
private:
    RpcConnection();

    // FIXME: support a list of connctions
    // FIXME: unique_fd to add libbase dep to libbinder?
    int mFd;
};

} // namespace android
