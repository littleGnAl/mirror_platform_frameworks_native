/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "adbwifi/pairing/pairing_auth.h"

#include <adbwifi/crypto/aes_128_gcm.h>

#include <android-base/logging.h>

#include <openssl/curve25519.h>
#include <openssl/mem.h>

#include <iomanip>
#include <sstream>
#include <vector>

namespace adbwifi {
namespace pairing {

namespace {

static constexpr spake2_role_t kClientRole = spake2_role_alice;
static constexpr spake2_role_t kServerRole = spake2_role_bob;

static const uint8_t kClientName[] = "adb pair client";
static const uint8_t kServerName[] = "adb pair server";

// This class is basically a wrapper around the SPAKE2 protocol + initializing a
// cipher with the generated key material for encryption.
class PairingAuthImpl : public PairingAuth {
public:
    virtual ~PairingAuthImpl() = default;

    explicit PairingAuthImpl(Role role,
                             const Data& pswd);

    // Returns the message to exchange with the other party. This can return an
    // empty message if spake2_generate_msg() failed, at which this object
    // becomes useless. So destroy this object if so.
    virtual const Data& msg() const override;

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
    virtual bool initCipher(const Data& their_msg) override;

    // Encrypts |data| and returns the result. If encryption fails, the return
    // will be an empty vector.
    virtual Data encrypt(const Data& data) override;

    // Decrypts |data| and returns the result. If decryption fails, the return
    // will be an empty vector.
    virtual Data decrypt(const Data& data) override;

private:
    enum class State {
        Invalid,
        ProcessPeerKey,
        CipherInited,
    };
    State state_ = State::Invalid;
    Data our_msg_;
    Role role_;
    bssl::UniquePtr<SPAKE2_CTX> spake2_ctx_;
    std::unique_ptr<crypto::Aes128Gcm> cipher_;
};  // PairingAuthImpl

PairingAuthImpl::PairingAuthImpl(Role role,
                                 const Data& pswd) :
        role_(role) {
    if (pswd.empty()) {
        LOG(ERROR) << "Password cannot be empty.";
        return;
    }
    // Try to create the spake2 context and generate the public key.
    spake2_role_t spake_role;
    const uint8_t* my_name = nullptr;
    const uint8_t* their_name = nullptr;
    size_t my_len = 0;
    size_t their_len = 0;

    // Create the SPAKE2 context
    switch (role_) {
        case Role::Client:
            spake_role = kClientRole;
            my_name = kClientName;
            my_len = sizeof(kClientName);
            their_name = kServerName;
            their_len = sizeof(kServerName);
            break;
        case Role::Server:
            spake_role = kServerRole;
            my_name = kServerName;
            my_len = sizeof(kServerName);
            their_name = kClientName;
            their_len = sizeof(kClientName);
            break;
    }
    spake2_ctx_.reset(SPAKE2_CTX_new(spake_role,
                                       my_name,
                                       my_len,
                                       their_name,
                                       their_len));
    if (spake2_ctx_ == nullptr) {
        LOG(ERROR) << "Unable to create a SPAKE2 context.";
        return;
    }

    // Generate the SPAKE2 public key
    size_t key_size = 0;
    uint8_t key[SPAKE2_MAX_MSG_SIZE];
    int status = SPAKE2_generate_msg(spake2_ctx_.get(),
                                     key,
                                     &key_size,
                                     SPAKE2_MAX_MSG_SIZE,
                                     pswd.data(),
                                     pswd.size());
    if (status != 1 || key_size == 0) {
        LOG(ERROR) << "Unable to generate the SPAKE2 public key.";
        return;
    }
    our_msg_.assign(key, key + key_size);
    state_ = State::ProcessPeerKey;
}

const PairingAuth::Data& PairingAuthImpl::msg() const {
    return our_msg_;
}

bool PairingAuthImpl::initCipher(const PairingAuth::Data& their_msg) {
    // You can only register a key once.
    if (state_ != State::ProcessPeerKey) {
        LOG(ERROR) << "PairingAuth not in the correct state to process a peer msg.";
        return false;
    }

    if (their_msg.empty()) {
        LOG(ERROR) << "their_msg is empty";
        return false;
    }

    // Try to process their key to generate the key material.
    state_ = State::Invalid; // set here to allow only one try.

    // Don't even try to process a message over the SPAKE2_MAX_MSG_SIZE
    if (their_msg.size() > SPAKE2_MAX_MSG_SIZE) {
        LOG(ERROR) << "their_msg size [" << their_msg.size()
                   << "] greater then max size [" << SPAKE2_MAX_MSG_SIZE
                   << "].";
        return false;
    }

    size_t key_material_len = 0;
    uint8_t key_material[SPAKE2_MAX_KEY_SIZE];
    int status = SPAKE2_process_msg(spake2_ctx_.get(),
                                    key_material,
                                    &key_material_len,
                                    sizeof(key_material),
                                    reinterpret_cast<const uint8_t*>(their_msg.data()),
                                    their_msg.size());
    if (status != 1) {
        LOG(ERROR) << "Unable to process their public key";
        return false;
    }

    // Once SPAKE2_process_msg returns successfully, you can't do anything else
    // with the context, besides destroy it.
    cipher_.reset(new crypto::Aes128Gcm());
    if (!cipher_->init(key_material, key_material_len)) {
        LOG(ERROR) << "Unable to initialize cipher.";
        return false;
    }

    state_ = State::CipherInited;
    return true;
}

PairingAuth::Data PairingAuthImpl::encrypt(const PairingAuth::Data& data) {
    if (state_ != State::CipherInited || data.empty()) {
        LOG(ERROR) << "Can't encrypt. Either cipher not initialized or empty data.";
        return Data();
    }

    // Determine the size for the encrypted data based on the raw data.
    Data encrypted(cipher_->encryptedSize(data.size()));
    int bytes = cipher_->encrypt(reinterpret_cast<const uint8_t*>(data.data()),
                                  data.size(),
                                  encrypted.data(),
                                  encrypted.size());
    if (bytes < 0) {
        LOG(ERROR) << "Unable to encrypt data";
        return Data();
    }
    encrypted.resize(bytes);

    return encrypted;
}

PairingAuth::Data PairingAuthImpl::decrypt(const PairingAuth::Data& data) {
    if (state_ != State::CipherInited || data.empty()) {
        LOG(ERROR) << "Can't decrypt. Cipher invalid or input is empty.";
        return Data();
    }

    // Determine the size for the decrypted data based on the raw data.
    Data decrypted(cipher_->decryptedSize(reinterpret_cast<const uint8_t*>(data.data()), data.size()));
    size_t decryptedSize = decrypted.size();
    int bytes = cipher_->decrypt(reinterpret_cast<const uint8_t*>(data.data()),
                                  data.size(),
                                  decrypted.data(),
                                  &decryptedSize);
    if (bytes < 0) {
        LOG(ERROR) << "Unable to decrypt data";
        return Data();
    }
    decrypted.resize(decryptedSize);

    return decrypted;
}
}  // namespace

// static
std::unique_ptr<PairingAuth> PairingAuth::create(Role role,
                                                 const Data& pswd) {
    std::unique_ptr<PairingAuth> ret(new PairingAuthImpl(role, pswd));
    // The object is useless if the message is empty, so don't let the user use it.
    if (ret->msg().empty()) {
        return nullptr;
    }
    return ret;
}

}  // namespace pairing
}  // namespace adbwifi
