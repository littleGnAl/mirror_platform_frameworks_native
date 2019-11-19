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

#include <stddef.h>
#include <stdint.h>

#include <functional>
#include <memory>
#include <string_view>
#include <vector>

#include "adbwifi/pairing/pairing_header.h"

namespace adbwifi {
namespace pairing {

constexpr int kDefaultPairingPort = 51393;

// PairingConnection encapsulates the protocol to authenticate two peers with
// each other. This class will open the tcp sockets and handle the pairing
// process. On completion, both sides will have each other's public key
// (certificate) if successful, otherwise, the pairing failed. The tcp port
// number is hardcoded (see pairing_connection.cpp).
//
// Each PairingConnection instance represents a different device trying to
// pair. So for the device, we can have multiple PairingConnections while the
// host may have only one (unless host has a PairingServer).
//
// See pairing_connection_test.cpp for example usage.
//
class PairingConnection {
public:
    using Data = std::vector<uint8_t>;
    using ResultCallback = std::function<void(const PeerInfo* peer_info,
                                              const Data* certificate,
                                              void* opaque)>;
    enum class Role {
        Client,
        Server,
    };

    virtual ~PairingConnection() = default;

    // Starts the pairing connection on a separate thread.
    // Upon completion, if the pairing was successful,
    // |cb| will be called with the peer information and certificate.
    // Otherwise, |cb| will be called with empty data. |fd| should already
    // be opened. PairingConnection will take ownership of the |fd|.
    //
    // Pairing is successful if both server/client uses the same non-empty
    // |pswd|, and they are able to exchange the information. |pswd| and
    // |certificate| must be non-empty. start() can only be called once in the
    // lifetime of this object.
    //
    // Returns true if the thread was successfully started, false otherwise.
    virtual bool start(int fd, ResultCallback cb, void* opaque) = 0;

    // Creates a new PairingConnection instance. May return null if unable
    // to create an instance. |pswd|, |certificate|, |priv_key|, and |peer_info|
    // cannot be empty.
    static std::unique_ptr<PairingConnection> create(Role role,
                                                     const Data& pswd,
                                                     const PeerInfo& peer_info,
                                                     const Data& certificate,
                                                     const Data& priv_key);

protected:
    PairingConnection() = default;
};  // class PairingConnection

}  // namespace pairing
}  // namespace adbwifi
