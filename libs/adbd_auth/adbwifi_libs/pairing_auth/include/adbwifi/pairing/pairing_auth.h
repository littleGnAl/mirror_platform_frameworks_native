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

#include <memory>
#include <vector>

namespace adbwifi {
namespace pairing {

// PairingAuth is a wrapper around the SPAKE2 protocol + cipher initialization
// for encryption. On construction, the |password| will be used to generate a
// SPAKE2 message. Each peer will enchange the messages to initialize a cipher
// for encryption. If both peers used the same |password|, then both sides will
// be able to decrypt each other's messages.
//
// Important note: Each PairingAuth instance can only be used to pair with one
// other peer. Also, the peer only gets one chance at the password. If it's
// wrong, then |decrypt| will fail. You can only call |initCipher| once with a
// non-empty message. After |initCipher|, the only valid usage is to |encrypt|
// and |decrypt|.
//
// The way to determine whether the peer used the same password is by decrypting
// an encrypted message from them. If |decrypt| returns true, then you can
// assume you both used the same password, and can be trusted.
//
// Example usage (each peer will do the same):
//
//   // 1) Create a PairingAuth instance
//   std::vector<uint8_t> pswd{...};
//   auto auth = PairingAuth::create(pswd);
//
//   // 2) Retrieve message
//   auto my_msg = auth->msg();
//   // Send |my_msg| to peer ...
//
//   ...
//
//   // 3) ... Receive peer's message ...
//   // ... and initialize our cipher with it.
//   auth->initCipher(their_msg);
//
//   // 4) Encrypt a message for the peer to decrypt and send it to them
//   auto encrypted = auth->encrypt(...);
//   // sending |encrypted| ...
//
//   ...
//
//   // 5) Receive peer's encrypted message...
//   // ... now try to decrypt it.
//   auto decrypted = auth->decrypt(...);
//   if (!decrypted.empty()) {
//      // The peer used the same password! You can do further processing
//      // here if needed.
//   }
//
// See pairing_auth_test.cpp for example usage.
class PairingAuth {
public:
    using Data = std::vector<uint8_t>;
    enum class Role {
        Client,
        Server,
    };

    virtual ~PairingAuth() = default;

    // Returns the message to exchange with the other party. This is guaranteed
    // to have a non-empty message if creating this object with
    // |PairingAuth::create|, so you won't need to check.
    virtual const Data& msg() const = 0;

    // Processes the peer's |msg| and attempts to initialize the cipher for
    // encryption. You can only call this method ONCE with a non-empty |msg|,
    // regardless of success or failure. Subsequent calls will always return
    // false. On success, you can use the |decrypt|
    // and |encrypt| methods to exchange any further information securely.
    //
    // Note: Once you call this with a non-empty key, the state is locked, which
    // means that you cannot try and register another key, regardless of the
    // return value. In order to register another key, you have to create a new
    // instance of PairingAuth.
    virtual bool initCipher(const Data& their_msg) = 0;

    // Encrypts |data| and returns the result. If encryption fails, the return
    // will be an empty vector.
    virtual Data encrypt(const Data& data) = 0;

    // Decrypts |data| and returns the result. If decryption fails, the return
    // will be an empty vector.
    virtual Data decrypt(const Data& data) = 0;

    // Creates a new PairingAuth instance. May return null if unable
    // to create an instance. |pswd| cannot be empty.
    static std::unique_ptr<PairingAuth> create(Role role,
                                               const Data& pswd);

protected:
    PairingAuth() = default;
};  // class PairingAuth

}  // namespace pairing
}  // namespace adbwifi
