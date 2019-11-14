/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
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

#include <memory>
#include <optional>
#include <string>
#include <string_view>

namespace adbwifi {
namespace crypto {

// This class maintains the device's GUID, short name, certificate, as well as
// the keystore of the trusted devices' GUID, short name, and certificates.
class KeyStore {
public:
    // The device's information: [guid, name, certificate, private_key]
    using DeviceInfo = std::optional<std::tuple<std::string, std::string, std::string, std::string>>;
    // The stored peer's information: [guid, name, certificate]
    using PeerInfo = std::optional<std::tuple<std::string, std::string, std::string>>;

    virtual ~KeyStore() = default;

    // Get the device's info. May be empty if unable to read the key files.
    virtual DeviceInfo getDeviceInfo() const = 0;

    // Store the information of a peer into the keystore.
    virtual bool storePeerInfo(const PeerInfo& info) = 0;

    // Try to retrieve the peer's information from the keystore by their guid.
    // PeerInfo will be empty on failure.
    virtual PeerInfo getPeerInfo(std::string_view guid) = 0;

    // Returns the size of the keystore.
    virtual size_t size() const = 0;

    // index operator to traverse the list of keys in the keystore. The first in
    // the pair is the guid, and the second is the corresponding peer
    // information.
    virtual std::pair<std::string, PeerInfo> operator[](const size_t idx) const = 0;

    // Tries to create a KeyStore instance. This will return null if it was
    // unable to read or create the GUID, short name, certificate and private
    // key of the device. This can happen if, for example, adbd tries to read
    // it before the data partition is mounted.
    static std::unique_ptr<KeyStore> create(std::string_view keystore_path);
protected:
    KeyStore() = default;
};  // KeyStore

}  // namespace crypto
}  // namespace adbwifi
