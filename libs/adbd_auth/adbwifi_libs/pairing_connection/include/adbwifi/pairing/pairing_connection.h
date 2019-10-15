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
#include <string_view>
#include <vector>

namespace adbwifi {
namespace pairing {

// PairingConnection encapsulates the protocol to authenticate two peers with
// each other. This class will open the tcp sockets and handle the pairing
// process. On completion, both sides will have each other's public key
// (certificate) if successful, otherwise, the pairing failed. The tcp port
// number is hardcoded (see pairing_connection.cpp).
//
// Server:
//
// Upon calling start(), the server will open a port to listen for client
// connections. For each client connection, the server and client will try to
// establish the pairing. The process is synchonized per client, so only one can
// establish the pairing per server instance.
//
// See pairing_connection_test.cpp for example usage.
class PairingConnection {
public:
    using Data = std::vector<uint8_t>;
    using ResultCallback = std::function<void(const Data& cert, void* opaque)>;
    enum class Role {
        Client,
        Server,
    };

    virtual ~PairingConnection() = default;

    // Starts the pairing connection. This call spawns another thread to handle
    // the pairing. Upon completion, if the pairing was successful,
    // then |cb| will be called with the certificate. Otherwise, |cb| will be
    // called with an empty value.
    //
    // Pairing is successful if both server/client uses the same non-empty
    // |pswd|, and they are able to exchange the information. |pswd| and
    // |certificate| must be non-empty. start() can only be called once in the
    // lifetime of this object.
    // Returns true if the thread was successfully started, false otherwise. You
    // can only start() once.
    virtual bool start(ResultCallback cb, void* opaque) = 0;

    // Cancels the pairing connection. This will force the connection to close.
    // You should still expect |cb| to be called.
    virtual void stop() = 0;

    // Waits for the start() thread to finish.
    virtual void wait() = 0;

    // Creates a new PairingConnection instance. May return null if unable
    // to create an instance. |pswd| and |certificate| cannot be empty. For
    // |ip_addr|, it has to be a valid address for Role::Client. For
    // Role::Server, it is unused.
    static std::unique_ptr<PairingConnection> create(Role role,
                                                     const Data& pswd,
                                                     const Data& certificate,
                                                     std::string_view ip_addr = "");

protected:
    PairingConnection() = default;
};  // class PairingConnection

}  // namespace pairing
}  // namespace adbwifi
