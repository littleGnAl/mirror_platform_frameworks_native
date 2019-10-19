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

#include "pairing/pairing_auth.h"

#include "crypto/aes_128_gcm.h"

#include <android-base/logging.h>

#include <openssl/curve25519.h>
#include <openssl/mem.h>

#include <vector>

//#include <android-base/logging.h>

//#include "crypto/identifiers.h"
//#include "crypto/key_type.h"
//#include "fdevent/fdevent.h"
//#include "sysdeps.h"

namespace {

static constexpr spake2_role_t kClientRole = spake2_role_alice;
static constexpr spake2_role_t kServerRole = spake2_role_bob;

static const uint8_t kClientName[] = "adb pair client";
static const uint8_t kServerName[] = "adb pair server";

const uint32_t kMaxKeySize = 32;

// Helper class to secure the pairing authentication communication
// between the adb client and server.
class PairingAuth {
public:
    using Data = std::vector<uint8_t>;
    using DataHolder = std::string_view;
    static DataHolder makeDataHolder(const uint8_t* data,
                                     uint64_t size) {
        return DataHolder(reinterpret_cast<const char*>(data),
                          size);
    }

    virtual ~PairingAuth() = default;

    // Returns the public key to exchange with the other party. This is
    // guaranteed to have a valid public key.
    const Data& publicKey() const;
    // Registers in the other party's public key, |theirKey|, to generate
    // the key material to encrypt further messages. You must call this
    // prior using the encrypt() and decrypt() functions, otherwise, those
    // functions will return empty. This function returns true if the |theirKey|
    // was successfully registered, false otherwise.
    bool registerPublicKey(DataHolder theirKey);
    // Returns the size needs to encrypt |data| amount of data.
    uint64_t encryptedSize(uint64_t dataSize);
    // Encrypts |data| and returns the result. If encryption fails, the return
    // will be an empty vector.
    Data&& encrypt(DataHolder data);
    // Returns the size needed to decrypt |data|.
    uint64_t decryptedSize(DataHolder data);
    // Decrypts |data| and returns the result. If decryption fails, the return
    // will be an empty vector.
    Data&& decrypt(DataHolder data);
    // Identifies whether the object is in a usable state. Once the object
    // is invalid, it will always be invalid and should be discarded.
    bool isValid() const;
    // Returns the maximum size a pairing request packet can have.
    uint32_t maxPairingRequestSize();
    // Creates and returns a pairing request packet. On failure, the packet
    // returned will be empty.
    Data&& createPairingRequest();
    // Reads and attempts to parse the pairing request packet |pkt|. On success,
    // |header| will be filled, and return will be true. False otherwise.
    bool readPairingRequest(DataHolder pkt,
                            PublicKeyHeader* header);

    // Creates a new PairingAuth instance. May return null if unable
    // to create an instance.
    static PairingAuth* create(PairingRole role,
                               const uint8_t* pswd,
                               uint64_t pswdSize);

protected:
    explicit PairingAuth(PairingRole role,
                         const uint8_t* pswd,
                         uint64_t pswdSize);

private:
    Data mOurPublicKey;
    Data mTheirPublicKey;
    Data mKeyMaterial;
    PairingRole mRole;
    bool mIsValid = false;
    bssl::UniquePtr<SPAKE2_CTX> mSPAKE2Ctx;
    crypto::Aes128Gcm mCipher;
};  // PairingAuth

PairingAuth::PairingAuth(PairingRole role,
                         const uint8_t* pswd,
                         uint64_t pswdSize) :
        mRole(role) {
    if (pswd == nullptr || pswdSize == 0) {
        LOG(ERROR) << "Password is invalid";
        return;
    }
    // Try to create the spake2 context and generate the public key.
    spake2_role_t spakeRole;
    const uint8_t* myName = nullptr;
    const uint8_t* theirName = nullptr;
    size_t myLen = 0;
    size_t theirLen = 0;

    // Create the SPAKE2 context
    switch (mRole) {
        case PairingRole::Client:
            spakeRole = kClientRole;
            myName = kClientName;
            myLen = sizeof(kClientName);
            theirName = kServerName;
            theirLen = sizeof(kServerName);
            break;
        case PairingRole::Server:
            spakeRole = kServerRole;
            myName = kServerName;
            myLen = sizeof(kServerName);
            theirName = kClientName;
            theirLen = sizeof(kClientName);
            break;
    }
    mSPAKE2Ctx.reset(SPAKE2_CTX_new(spakeRole,
                                    myName,
                                    myLen,
                                    theirName,
                                    theirLen));
    if (mSPAKE2Ctx == nullptr) {
        LOG(ERROR) << "Unable to create a SPAKE2 context.";
        return;
    }

    // Generate the SPAKE2 public key
    size_t keySize = 0;
    uint8_t key[SPAKE2_MAX_MSG_SIZE];
    int status = SPAKE2_generate_msg(mSPAKE2Ctx.get(),
                                     key,
                                     &keySize,
                                     SPAKE2_MAX_MSG_SIZE,
                                     pswd,
                                     pswdSize);
    if (status != 1) {
        LOG(ERROR) << "Unable to generate the SPAKE2 public key.";
        return;
    }
    mOurPublicKey.assign(key, key + keySize);

    mIsValid = true;
}

const PairingAuth::Data& PairingAuth::publicKey() const {
    return mOurPublicKey;
}

bool PairingAuth::registerPublicKey(PairingAuth::DataHolder theirKey) {
    if (theirKey.empty()) {
        LOG(ERROR) << "theirKey is empty";
        mIsValid = false;
        return false;
    }

    mTheirPublicKey.assign(theirKey.begin(), theirKey.end());
    // Try to process their key to generate the key material.
    size_t keyMaterialLen = 0;
    uint8_t keyMaterial[SPAKE2_MAX_KEY_SIZE];
    int status = SPAKE2_process_msg(mSPAKE2Ctx.get(),
                                    keyMaterial,
                                    &keyMaterialLen,
                                    sizeof(keyMaterial),
                                    reinterpret_cast<const uint8_t*>(theirKey.data()),
                                    theirKey.size());
    if (status != 1) {
        LOG(ERROR) << "Unable to process their public key";
        mIsValid = false;
        return false;
    }

    mKeyMaterial.assign(keyMaterial, keyMaterial + keyMaterialLen);

    if (mCipher.init(mKeyMaterial.data(), mKeyMaterial.size())) {
        mIsValid = false;
        return false;
    }

    return true;
}

uint64_t PairingAuth::encryptedSize(uint64_t dataSize) {
    if (!mIsValid || mTheirPublicKey.empty()) {
        return 0;
    }

    return mCipher.encryptedSize(dataSize);
}

PairingAuth::Data&& PairingAuth::encrypt(PairingAuth::DataHolder data) {
    if (!mIsValid || mTheirPublicKey.empty()) {
        LOG(ERROR) << "Can't encrypt. PairingAuth is invalid or hasn't gotten their public key yet.";
        return std::move(Data());
    }

    // Determine the size for the encrypted data based on the raw data.
    Data encrypted(mCipher.encryptedSize(data.size()));
    int bytes = mCipher.encrypt(reinterpret_cast<const uint8_t*>(data.data()),
                                data.size(),
                                encrypted.data(),
                                encrypted.size());
    if (bytes < 0) {
        LOG(ERROR) << "Unable to encrypt data";
        return std::move(Data());
    }
    encrypted.resize(bytes);

    return std::move(encrypted);
}

uint64_t PairingAuth::decryptedSize(PairingAuth::DataHolder data) {
    if (!mIsValid || mTheirPublicKey.empty() || data.empty()) {
        return 0;
    }

    return mCipher.decryptedSize(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

PairingAuth::Data&& PairingAuth::decrypt(PairingAuth::DataHolder data) {
    if (!mIsValid || mTheirPublicKey.empty()) {
        LOG(ERROR) << "Can't decrypt. PairingAuth is invalid or hasn't gotten their public key yet.";
        return std::move(Data());
    }

    // Determine the size for the decrypted data based on the raw data.
    Data decrypted(mCipher.decryptedSize(reinterpret_cast<const uint8_t*>(data.data()), data.size()));
    size_t decryptedSize = decrypted.size();
    int bytes = mCipher.decrypt(reinterpret_cast<const uint8_t*>(data.data()),
                                data.size(),
                                decrypted.data(),
                                &decryptedSize);
    if (bytes < 0) {
        LOG(ERROR) << "Unable to encrypt data";
        return std::move(Data());
    }
    decrypted.resize(decryptedSize);

    return std::move(decrypted);
}

bool PairingAuth::isValid() const {
    return mIsValid;
}

uint32_t PairingAuth::maxPairingRequestSize() {
    // Format of a request is as follows:
    // 2) Size of our SPAKE2 public key (4 bytes)
    // 3) our SPAKE2 public key (<= kMaxKeySize)
    // 4) Size of the encrypted PublicKeyHeader (8 bytes)
    // 5) The encrypted PublicKeyHeader data (? bytes)
    if (!isValid() || mTheirPublicKey.empty()) {
        return 0;
    }
    return 12 + kMaxKeySize + mCipher.encryptedSize(sizeof(PublicKeyHeader));
}

PairingAuth::Data&& PairingAuth::createPairingRequest() {
    Data pkt;

    if (!isValid() || mTheirPublicKey.empty()) {
        return std::move(Data());
    }

    uint32_t keySize = mOurPublicKey.size();
    auto* ptr8 = reinterpret_cast<uint8_t*>(&keySize);
    pkt.insert(pkt.end(), ptr8, ptr8 + sizeof(keySize));
    pkt.insert(pkt.end(), mOurPublicKey.data(), mOurPublicKey.data() + keySize);

    PublicKeyHeader header;
    header.version = kCurrentKeyHeaderVersion;
    // TODO: fill this in.
    header.type = 0;
    header.bits = 0;
    header.payload = 0;
    strncpy(header.name, "My Macbook", sizeof("My Macbook"));
    header.name[sizeof(header.name) - 1]  = '\0';
    strncpy(header.id, "Macbook1234", sizeof("Macbook1234"));
    header.id[sizeof(header.id) - 1]  = '\0';

    // Encrypt the PublicKeyHeader
    Data encrypted = encrypt(makeDataHolder(reinterpret_cast<uint8_t*>(&header),
                                            sizeof(PublicKeyHeader)));
    if (encrypted.empty()) {
        LOG(ERROR) << "Failed to encrypt the PublicKeyHeader";
        return std::move(Data());
    }
    uint64_t encryptedSize = encrypted.size();
    ptr8 = reinterpret_cast<uint8_t*>(&encryptedSize);
    pkt.insert(pkt.end(), ptr8, ptr8 + sizeof(encryptedSize));
    pkt.insert(pkt.end(), encrypted.data(), encrypted.data() + encryptedSize);

    return std::move(pkt);
}

bool PairingAuth::readPairingRequest(PairingAuth::DataHolder pkt,
                                     PublicKeyHeader* header) {
    if (!isValid() || pkt.empty()) {
        return false;
    }

    if (pkt.size() > maxPairingRequestSize()) {
        return false;
    }
    auto* data = reinterpret_cast<const uint8_t*>(pkt.data());
    int64_t remainingBytes = pkt.size();

    // extract their spake2 key.
    if (remainingBytes < 5) {
        LOG(ERROR) << "Not enough data in packet for public key (sz=" << pkt.size() << ")";
        return false;
    }
    uint32_t keySize = *reinterpret_cast<const uint32_t*>(data);
    if (keySize > kMaxKeySize) {
        LOG(ERROR) << "Bad key length [" << keySize << "]";
        return false;
    }
    data += 4;
    remainingBytes -= 4;

    // Ensure enough bytes to read public key and the encrypted data size
    if (remainingBytes < static_cast<int64_t>(keySize + sizeof(uint64_t))) {
        LOG(ERROR) << "Not enough bytes to read public key and encrypted data size";
    }
    mTheirPublicKey.assign(data, data + keySize);

    data += keySize;
    remainingBytes -= keySize;
    // Read the encrypted PublicKeyHeader
    uint64_t encryptedSz = *reinterpret_cast<const uint64_t*>(data);
    auto expectedEncryptedSz = encryptedSize(sizeof(PublicKeyHeader));
    if (encryptedSz != expectedEncryptedSz) {
        LOG(ERROR) << "Encrypted size=[" << encryptedSz << "] does not match expected size=["
                   << expectedEncryptedSz << "]";
    }
    data += 8;
    remainingBytes -= 8;
    auto encrypted = makeDataHolder(data, remainingBytes < 0 ? 0 : remainingBytes);
    uint64_t decryptedSz = decryptedSize(encrypted);
    if (sizeof(PublicKeyHeader) != decryptedSz) {
        LOG(ERROR) << "Expected " << sizeof(PublicKeyHeader) << " bytes for PublicKeyHeader but "
                   << "got " << decryptedSz << " bytes";
        return false;
    }

    auto decrypted = decrypt(encrypted);
    if (decrypted.empty() || decrypted.size() != sizeof(PublicKeyHeader)) {
        LOG(ERROR) << "Failed to decrypt the PublicKeyHeader";
        return false;
    }

    memcpy(header, decrypted.data(), decrypted.size());
    return true;
}

// static
PairingAuth* PairingAuth::create(PairingRole role,
                                 const uint8_t* pswd,
                                 uint64_t pswdSize) {
    auto* p = new PairingAuth(role, pswd, pswdSize);
    if (!p->isValid()) {
        delete p;
        return nullptr;
    }
    return p;
}
}  // namespace

PairingAuthCtx pairing_auth_new_ctx(PairingRole role,
                                    const uint8_t* pswd,
                                    uint64_t pswdSize) {
    auto* p = PairingAuth::create(role, pswd, pswdSize);
    if (p != nullptr) {
        if (!p->isValid()) {
          delete p;
          return nullptr;
        } else {
          return static_cast<void*>(p);
        }
    }
    return nullptr;
}

void pairing_auth_delete_ctx(PairingAuthCtx ctx) {
    auto* p = static_cast<PairingAuth*>(ctx);
    if (p != nullptr) {
        delete p;
    }
}

int pairing_auth_our_public_key(PairingAuthCtx ctx, uint8_t* buffer) {
    auto* p = static_cast<PairingAuth*>(ctx);

    if (!p->isValid()) {
        return 0;
    }
    auto key = p->publicKey();
    memcpy(buffer, key.data(), key.size());

    return key.size();
}

bool pairing_auth_register_their_key(PairingAuthCtx ctx,
                                     const uint8_t* theirKey,
                                     uint64_t theirKeySize) {
    auto* p = static_cast<PairingAuth*>(ctx);

    if (!p->isValid()) {
        return false;
    }
    return p->registerPublicKey(PairingAuth::makeDataHolder(theirKey,
                                                            theirKeySize));
}

uint64_t pairing_auth_decrypted_size(PairingAuthCtx ctx,
                                     const uint8_t* encrypted,
                                     uint64_t sz) {
    auto* p = static_cast<PairingAuth*>(ctx);
    return p->decryptedSize(PairingAuth::makeDataHolder(encrypted, sz));
}

bool pairing_auth_decrypt(PairingAuthCtx ctx,
                          const uint8_t* msg,
                          uint64_t msgSize,
                          uint8_t* out,
                          uint64_t* outSize) {
    auto* p = static_cast<PairingAuth*>(ctx);

    if (!p->isValid()) {
        return false;
    }

    auto decrypted = p->decrypt(PairingAuth::makeDataHolder(msg, msgSize));
    if (decrypted.empty()) {
        LOG(ERROR) << "Unable to decrypt message";
        return false;
    }

    *outSize = decrypted.size();
    memcpy(out, decrypted.data(), *outSize);

    return true;
}

uint64_t pairing_auth_encrypted_size(PairingAuthCtx ctx,
                                     uint64_t dataSize) {
    auto* p = static_cast<PairingAuth*>(ctx);
    return p->encryptedSize(dataSize);
}

bool pairing_auth_encrypt(PairingAuthCtx ctx,
                          const uint8_t* msg,
                          uint64_t msgSize,
                          uint8_t* out,
                          uint64_t* outSize) {
    auto* p = static_cast<PairingAuth*>(ctx);

    if (!p->isValid()) {
        return false;
    }

    auto encrypted = p->encrypt(PairingAuth::makeDataHolder(msg, msgSize));
    if (encrypted.empty()) {
        LOG(ERROR) << "Unable to encrypt message";
        return false;
    }

    *outSize = encrypted.size();
    memcpy(out, encrypted.data(), *outSize);

    return true;
}

uint32_t pairing_auth_max_key_size(PairingAuthCtx /* ctx */) {
    return kMaxKeySize;
}

uint32_t pairing_auth_request_max_size(PairingAuthCtx ctx) {
    auto* p = static_cast<PairingAuth*>(ctx);
    return p->maxPairingRequestSize();
}

bool pairing_auth_create_request(PairingAuthCtx ctx,
                                 uint8_t* pkt,
                                 uint32_t* pktSize) {
    auto* p = static_cast<PairingAuth*>(ctx);

    if (!p->isValid()) {
        return false;
    }

    auto result = p->createPairingRequest();
    if (result.empty()) {
        LOG(ERROR) << "Unable to create pairing request message";
        return false;
    }

    *pktSize = result.size();
    memcpy(pkt, result.data(), *pktSize);

    return true;
}

bool pairing_auth_parse_request(PairingAuthCtx ctx,
                                const uint8_t* pkt,
                                uint32_t pktSize,
                                PublicKeyHeader* out) {
    auto* p = static_cast<PairingAuth*>(ctx);

    if (!p->isValid()) {
        return false;
    }

    if (!p->readPairingRequest(PairingAuth::makeDataHolder(pkt, pktSize),
                               out)) {
        LOG(ERROR) << "Unable to read the pairing request message.";
        return false;
    }

    if (out->version <= kMinSupportedKeyHeaderVersion ||
        out->version >= kMaxSupportedKeyHeaderVersion) {
        LOG(ERROR) << "Unsupported PublicKeyHeader version. Unable to parse."
                   << " current version (" << kCurrentKeyHeaderVersion << ")"
                   << " packet version (" << out->version << ")"
                   << " min supported version (" << kMinSupportedKeyHeaderVersion << ")"
                   << " max supported version (" << kMaxSupportedKeyHeaderVersion << ")";
        return false;
    }

    return true;
}
