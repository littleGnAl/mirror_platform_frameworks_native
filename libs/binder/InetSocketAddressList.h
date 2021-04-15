/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include <string>
#include <string_view>

#include <binder/RpcConnection.h>

namespace android {

// A linked list of inet RpcConnection::SocketAddress.
class InetSocketAddressList {
public:
    using value_type = RpcConnection::SocketAddress;
    class InetSocketAddress;
    class const_iterator;

    static InetSocketAddressList GetAddrInfo(const char* addr, unsigned int port);
    [[nodiscard]] const_iterator begin() const;
    [[nodiscard]] const_iterator end() const;

private:
    friend class InetSocketAddressListTestHelper;
    friend class InetSocketAddressListTest;
    using AddrInfo = std::unique_ptr<addrinfo, decltype(&freeaddrinfo)>;

    // Construct an empty list of InetSocketAddress.
    InetSocketAddressList() : InetSocketAddressList(nullptr, {}) {}
    // Construct an list of InetSocketAddress starting from |head|.
    InetSocketAddressList(addrinfo* head, std::string_view desc)
          : InetSocketAddressList(AddrInfo(head, &freeaddrinfo), desc) {}
    // For testing
    InetSocketAddressList(AddrInfo head, std::string_view desc)
          : mHead(std::move(head)), mDesc(desc) {}

    AddrInfo mHead;
    std::string mDesc;
};

class InetSocketAddressList::InetSocketAddress : public RpcConnection::SocketAddress {
public:
    [[nodiscard]] std::string toString() const override { return std::string(mDesc); }
    [[nodiscard]] const sockaddr* addr() const override { return mAddr; }
    [[nodiscard]] size_t addrSize() const override { return mSize; }

private:
    friend InetSocketAddressList::const_iterator;

    // Caller (InetSocketAddressList) is responsible for maintaining the lifetime of |desc|.
    InetSocketAddress(const sockaddr* addr, size_t size, std::string_view desc)
          : mAddr(addr), mSize(size), mDesc(desc) {}

    const sockaddr* mAddr;
    size_t mSize;
    std::string_view mDesc;
};

class InetSocketAddressList::const_iterator
      : public std::iterator<std::input_iterator_tag, const InetSocketAddressList::value_type> {
public:
    const_iterator(addrinfo* ainfo, std::string_view desc) : mSockAddr(nullptr, 0, desc) {
        set(ainfo);
    }
    inline const_iterator& operator++() {
        set(mAddrInfo->ai_next);
        return *this;
    }
    inline const value_type& operator*() const { return mSockAddr; }
    inline const value_type* operator->() const { return &(operator*()); }
    inline bool operator==(const const_iterator& rhs) const { return mAddrInfo == rhs.mAddrInfo; }
    inline bool operator!=(const const_iterator& rhs) const { return mAddrInfo != rhs.mAddrInfo; }

private:
    addrinfo* mAddrInfo = nullptr;
    InetSocketAddress mSockAddr;
    void set(addrinfo* ainfo) {
        mAddrInfo = ainfo;
        if (mAddrInfo == nullptr) {
            mSockAddr.mAddr = nullptr;
            mSockAddr.mSize = 0;
        } else {
            mSockAddr.mAddr = mAddrInfo->ai_addr;
            mSockAddr.mSize = mAddrInfo->ai_addrlen;
        }
    }
};

inline InetSocketAddressList::const_iterator InetSocketAddressList::begin() const {
    return const_iterator(mHead.get(), mDesc);
}

inline InetSocketAddressList::const_iterator InetSocketAddressList::end() const {
    return const_iterator(nullptr, mDesc);
}

} // namespace android
