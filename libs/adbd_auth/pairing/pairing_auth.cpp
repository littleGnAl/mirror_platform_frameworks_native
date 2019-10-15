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

#include <android-base/endian.h>
#include <android-base/logging.h>

#include <openssl/curve25519.h>
#include <openssl/mem.h>

#include <iomanip>
#include <sstream>
#include <vector>

//#include "crypto/identifiers.h"
//#include "crypto/key_type.h"

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
    Data encrypt(DataHolder data);
    // Returns the size needed to decrypt |data|.
    uint64_t decryptedSize(DataHolder data);
    // Decrypts |data| and returns the result. If decryption fails, the return
    // will be an empty vector.
    Data decrypt(DataHolder data);
    // Identifies whether the object is in a usable state. Once the object
    // is invalid, it will always be invalid and should be discarded.
    bool isValid() const;
    // Returns the maximum size a pairing request packet can have.
    static uint32_t maxPairingRequestSize();
    // Creates and returns a pairing request packet. On failure, the packet
    // returned will be empty.
    Data createPairingRequest(const PublicKeyHeader* header,
                              const char* public_key);
    // Reads and attempts to parse the pairing request packet |pkt|. On success,
    // |out_header| and |out_public_key| will be filled, and return will be true.
    // False otherwise.
    bool readPairingRequest(DataHolder pkt,
                            PublicKeyHeader* out_header,
                            std::string& out_public_key);

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

static void dumpBytes(const char* name, const uint8_t* bytes, uint64_t szBytes) {
    LOG(INFO) << __func__ << "(name=" << name << " sz=" << szBytes << ")";
    LOG(INFO) << "======================================";
    std::stringstream output;
    const uint64_t numBytesPerLine = 8;
    for (uint64_t i = 0; i < szBytes;) {
        for (uint64_t j = 0; j < numBytesPerLine; ++j) {
            if (i == szBytes) {
                break;
            }
            output << std::setfill('0') << std::setw(2) << std::hex << static_cast<int>(bytes[i]);
            output << ' ';
            ++i;
        }
        if (i < szBytes) {
            output << '\n';
        }
    }
    LOG(INFO) << output.str();
    LOG(INFO) << "======================================";
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
    dumpBytes("keyMaterial", keyMaterial, keyMaterialLen);

    if (!mCipher.init(mKeyMaterial.data(), mKeyMaterial.size())) {
        LOG(ERROR) << "Unable to initialize cipher.";
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

PairingAuth::Data PairingAuth::encrypt(PairingAuth::DataHolder data) {
    if (!mIsValid || mTheirPublicKey.empty()) {
        LOG(ERROR) << "Can't encrypt. PairingAuth is invalid or hasn't gotten their public key yet.";
        return Data();
    }

    // Determine the size for the encrypted data based on the raw data.
    Data encrypted(mCipher.encryptedSize(data.size()));
    int bytes = mCipher.encrypt(reinterpret_cast<const uint8_t*>(data.data()),
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

uint64_t PairingAuth::decryptedSize(PairingAuth::DataHolder data) {
    if (!mIsValid || mTheirPublicKey.empty() || data.empty()) {
        return 0;
    }

    return mCipher.decryptedSize(reinterpret_cast<const uint8_t*>(data.data()), data.size());
}

PairingAuth::Data PairingAuth::decrypt(PairingAuth::DataHolder data) {
    if (!mIsValid || mTheirPublicKey.empty()) {
        LOG(ERROR) << "Can't decrypt. PairingAuth is invalid or hasn't gotten their public key yet.";
        return Data();
    }

    // Determine the size for the decrypted data based on the raw data.
    Data decrypted(mCipher.decryptedSize(reinterpret_cast<const uint8_t*>(data.data()), data.size()));
    size_t decryptedSize = decrypted.size();
    int bytes = mCipher.decrypt(reinterpret_cast<const uint8_t*>(data.data()),
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

bool PairingAuth::isValid() const {
    return mIsValid;
}

// static
uint32_t PairingAuth::maxPairingRequestSize() {
    // Format of a request is as follows:
    // 2) Size of our SPAKE2 public key (4 bytes)
    // 3) our SPAKE2 public key (<= kMaxKeySize)
    // 4) Size of the encrypted data (4 bytes)
    // 5) The encrypted data (? bytes)
    //
    // Let's just give a reasonably large enough size, because in order to
    // determine the size of the encrypted data, we need to initialize the
    // cipher, which we may not have yet.
    return 8192;
}

PairingAuth::Data PairingAuth::createPairingRequest(const PublicKeyHeader* header,
                                                    const char* public_key) {
    Data pkt;

    if (!isValid() || mTheirPublicKey.empty()) {
        return Data();
    }

    // Write out our SPAKE2 public key
    uint32_t keySize = htonl(mOurPublicKey.size());
    auto* ptr8 = reinterpret_cast<uint8_t*>(&keySize);
    // Size of our public key
    pkt.insert(pkt.end(), ptr8, ptr8 + sizeof(keySize));
    // our public key
    pkt.insert(pkt.end(), mOurPublicKey.data(), mOurPublicKey.data() + mOurPublicKey.size());

    // Encrypt the PublicKeyHeader and |public_key|
    //
    // Make another header, but in network format.
    Data public_key_info;
    PublicKeyHeader headernl;
    memcpy(reinterpret_cast<uint8_t*>(&headernl),
           reinterpret_cast<const uint8_t*>(header),
           sizeof(PublicKeyHeader));
    headernl.bits = htonl(headernl.bits);
    headernl.payload = htonl(headernl.payload);
    // Prep the public key header and the public key for encryption
    auto* hp = reinterpret_cast<uint8_t*>(&headernl);
    public_key_info.assign(hp, hp + sizeof(headernl));
    public_key_info.insert(public_key_info.end(), public_key, public_key + header->payload);
    dumpBytes("public_key_info", public_key_info.data(), public_key_info.size());

    // Encrypt public_key_info
    Data encrypted = encrypt(makeDataHolder(public_key_info.data(),
                                            public_key_info.size()));
    if (encrypted.empty()) {
        LOG(ERROR) << "Failed to encrypt the PublicKeyHeader";
        return Data();
    }

    // Write the encrypted data
    uint32_t encryptedSz = htonl(encrypted.size());
    ptr8 = reinterpret_cast<uint8_t*>(&encryptedSz);
    // Size of the encrypted data
    pkt.insert(pkt.end(), ptr8, ptr8 + sizeof(encryptedSz));
    // the encrypted data
    pkt.insert(pkt.end(), encrypted.data(), encrypted.data() + encrypted.size());

    dumpBytes("PairingRequest", reinterpret_cast<const uint8_t*>(pkt.data()), pkt.size());
    return pkt;
}

bool PairingAuth::readPairingRequest(PairingAuth::DataHolder pkt,
                                     PublicKeyHeader* out_header,
                                     std::string& out_public_key) {
    if (!isValid() || pkt.empty()) {
        return false;
    }

    if (pkt.size() > maxPairingRequestSize()) {
        return false;
    }
    dumpBytes("PairingRequest", reinterpret_cast<const uint8_t*>(pkt.data()), pkt.size());
    auto* data = reinterpret_cast<const uint8_t*>(pkt.data());
    int64_t remainingBytes = pkt.size();

    // extract their spake2 key.
    if (remainingBytes < 5) {
        LOG(ERROR) << "Not enough data in packet for public key (sz=" << pkt.size() << ")";
        return false;
    }
    // Get SPAKE2 key size
    uint32_t keySize = ntohl(*reinterpret_cast<const uint32_t*>(data));
    LOG(INFO) << "Public key size=" << keySize;
    if (keySize > kMaxKeySize) {
        LOG(ERROR) << "Bad key length [" << keySize << "]";
        return false;
    }
    data += 4;
    remainingBytes -= 4;

    // Ensure enough bytes to read SPAKE2 key and the encrypted data size
    if (remainingBytes < static_cast<int64_t>(keySize + sizeof(uint32_t))) {
        LOG(ERROR) << "Not enough bytes to read public key and encrypted data size";
    }

    // In the case as where the key material was already generated, let's just
    // use that to try and decrypt the encrypted part of the pairing message.
    // This can happen on the client side, when we generated the pairing
    // request, then server sends down their pairing request.
    if (mKeyMaterial.empty()) {
        // Register the SPAKE2 key to decrypt the message.
        if (!registerPublicKey(makeDataHolder(data, keySize))) {
            return false;
        }
    }

    data += keySize;
    remainingBytes -= keySize;
    // Read the encrypted data size
    uint32_t encryptedSz = ntohl(*reinterpret_cast<const uint32_t*>(data));
    data += 4;
    remainingBytes -= 4;

    if (remainingBytes < static_cast<int64_t>(encryptedSz)) {
        LOG(ERROR) << "Not enough bytes for encrypted size [size=" << encryptedSz
                   << ", remaining=" << remainingBytes << "]";
        return false;
    }
    auto encrypted = makeDataHolder(data, encryptedSz);
    auto decrypted = decrypt(encrypted);
    if (decrypted.empty() || decrypted.size() < sizeof(PublicKeyHeader)) {
        LOG(ERROR) << "decryption size [" << decrypted.size()
                   << " bytes] less then the PublicKeyHeader size ["
                   << sizeof(PublicKeyHeader) << " bytes]";
        return false;
    }

    // Write the public key header out
    memcpy(reinterpret_cast<uint8_t*>(out_header), decrypted.data(), sizeof(PublicKeyHeader));
    if (out_header->version < kMinSupportedKeyHeaderVersion ||
        out_header->version > kMaxSupportedKeyHeaderVersion) {
        LOG(ERROR) << "Unsupported PublicKeyHeader version. Unable to parse."
                   << " current version (" << (uint32_t)kCurrentKeyHeaderVersion << ")"
                   << " packet version (" << (uint32_t)out_header->version << ")"
                   << " min supported version (" << (uint32_t)kMinSupportedKeyHeaderVersion << ")"
                   << " max supported version (" << (uint32_t)kMaxSupportedKeyHeaderVersion << ")";
        return false;
    }
    out_header->bits = ntohl(out_header->bits);
    out_header->payload = ntohl(out_header->payload);
    // Ensure the name and id are null-terminated
    out_header->name[sizeof(out_header->name) - 1] = '\0';
    out_header->id[sizeof(out_header->id) - 1] = '\0';

    if (decrypted.size() < sizeof(PublicKeyHeader) + out_header->payload) {
        LOG(ERROR) << "Payload size (" << out_header->payload << " bytes) "
                   << "differs from actual size (" << decrypted.size() - sizeof(PublicKeyHeader)
                   << " bytes)";
        return false;
    }

    // Write the public key out
    out_public_key.assign(reinterpret_cast<const char*>(decrypted.data() + sizeof(PublicKeyHeader)),
                          out_header->payload);

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

uint32_t pairing_auth_request_max_size() {
    return PairingAuth::maxPairingRequestSize();
}

bool pairing_auth_create_request(PairingAuthCtx ctx,
                                 const PublicKeyHeader* header,
                                 const char* public_key,
                                 uint8_t* pkt,
                                 uint32_t* pktSize) {
    auto* p = static_cast<PairingAuth*>(ctx);

    if (!p->isValid()) {
        return false;
    }

    auto result = p->createPairingRequest(header, public_key);
    if (result.empty()) {
        LOG(ERROR) << "Unable to create pairing request message";
        return false;
    }

    *pktSize = result.size();
    memcpy(pkt, result.data(), *pktSize);

    return true;
}

static void dumpPublicKeyHeader(const PublicKeyHeader* h) {
    LOG(INFO) << "========== PublicKeyHeader:"
              << "\nversion=" << (uint32_t)h->version
              << "\ntype=" << (uint32_t)h->type
              << "\nbits=" << h->bits
              << "\npayload=" << h->payload
              << "\nname=[" << h->name << "]"
              << "\nid=[" << h->id << "]";
}

bool pairing_auth_parse_request(PairingAuthCtx ctx,
                                const uint8_t* pkt,
                                uint32_t pktSize,
                                PublicKeyHeader* out_header,
                                char* out_public_key) {
    auto* p = static_cast<PairingAuth*>(ctx);

    if (!p->isValid()) {
        return false;
    }

    std::string key;
    if (!p->readPairingRequest(PairingAuth::makeDataHolder(pkt, pktSize),
                               out_header,
                               key)) {
        LOG(ERROR) << "Unable to read the pairing request message.";
        return false;
    }

    key.copy(out_public_key, key.size());
    dumpPublicKeyHeader(out_header);

    return true;
}
