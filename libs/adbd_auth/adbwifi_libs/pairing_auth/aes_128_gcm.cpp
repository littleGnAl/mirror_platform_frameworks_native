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

#include "adbwifi/pairing/aes_128_gcm.h"

#include <android-base/endian.h>
#include <android-base/logging.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hkdf.h>
#include <openssl/rand.h>

namespace adbwifi {
namespace pairing {

static const size_t kHkdfKeyLength = 256;

// Encrypted data size = decrypted data size + padding. Padding is added
// if the decrypted data size is not a multiple of the encryption block size.
struct Header {
    // The actual length of the encrypted data without padding.
    uint32_t length;
    // The amount of padding added during the encryption. EVP_MAX_IV_LENGTH(16)
    // is the max block size for all ciphers, so let's just use one byte here.
    uint8_t padding;
    uint8_t iv[AES_128_GCM_IV_SIZE];
    uint8_t tag[AES_128_GCM_TAG_SIZE];
} __attribute__((packed));

// static
const EVP_CIPHER* Aes128Gcm::mCipher = EVP_aes_128_gcm();

bool Aes128Gcm::init(const uint8_t* keyMaterial, size_t keyMaterialLen) {
    if (keyMaterial == nullptr || keyMaterialLen == 0 || mInitialized) {
        LOG(ERROR) << "Key material is empty or cipher already inited";
        return false;
    }
    mContext.reset(EVP_CIPHER_CTX_new());
    if (mContext.get() == nullptr) {
        LOG(ERROR) << "EVP_CIPHER_CTX_new() returned null";
        return false;
    }

    // Start with a random number for our counter
    int status = RAND_bytes(mCounter.data(), mCounter.size());
    if (status != 1) {
        LOG(ERROR) << "RAND_bytes() failed";
        return false;
    }

    uint8_t key[kHkdfKeyLength] = {};
    uint8_t salt[64] = "this is the salt";
    uint8_t info[64] = "this is the info";
    status = HKDF(key, sizeof(key), EVP_sha256(),
                  keyMaterial, keyMaterialLen,
                  salt, sizeof(salt),
                  info, sizeof(info));
    if (status != 1) {
        LOG(ERROR) << "HKDF() failed";
        return false;
    }
    if (AES_set_encrypt_key(key, sizeof(key), &mAesKey) != 0) {
        LOG(ERROR) << "AES_set_encrypt_key() failed";
        return false;
    }
    mInitialized = true;
    return true;
}

int Aes128Gcm::encrypt(const uint8_t* in, size_t inLen,
                       uint8_t* out, size_t outLen) {
    if (outLen < encryptedSize(inLen)) {
        LOG(ERROR) << "out buffer size (sz=" << outLen << ") not big enough (sz="
                   << encryptedSize(inLen) << ")";
        return -1;
    }
    auto& header = *reinterpret_cast<Header*>(out);
    // Place the IV in the header
    memcpy(header.iv, mCounter.data(), mCounter.size());
    int status = EVP_EncryptInit_ex(mContext.get(),
                                    mCipher,
                                    nullptr,
                                    reinterpret_cast<const uint8_t*>(&mAesKey),
                                    mCounter.data());
    mCounter.increase();
    if (status != 1) {
        return -1;
    }

    int cipherLen = 0;
    out += sizeof(header);
    status = EVP_EncryptUpdate(mContext.get(), out, &cipherLen, in, inLen);
    if (status != 1 || cipherLen < 0) {
        return -1;
    }

    // Padding is enabled by default, so EVP_EncryptFinal_ex will pad any
    // remaining partial data up to the block size.
    int padding = 0;
    status = EVP_EncryptFinal_ex(mContext.get(), out + cipherLen, &padding);
    if (status != 1 || padding < 0) {
        return -1;
    }
    // We assume the padding size will fit into uint8_t.
    CHECK(padding <= 0xff);

    // Place the tag in the header
    status = EVP_CIPHER_CTX_ctrl(mContext.get(), EVP_CTRL_GCM_GET_TAG,
                                 sizeof(header.tag), header.tag);
    if (status != 1) {
        return -1;
    }
    // Place the length in the header
    uint32_t totalLen = sizeof(header) + cipherLen + padding;
    header.length = htonl(static_cast<uint32_t>(cipherLen));
    header.padding = padding;
    return totalLen;
}

int Aes128Gcm::decrypt(const uint8_t* in, size_t inLen,
                       uint8_t* out, size_t outLen) {
    if (inLen < sizeof(Header)) {
        return 0;
    }
    if (outLen < decryptedSize(in, inLen)) {
        return -1;
    }
    const auto& header = *reinterpret_cast<const Header*>(in);
    uint32_t dataLen = ntohl(header.length);
    uint32_t payloadLen = dataLen + header.padding;
    uint32_t totalLen = sizeof(Header) + payloadLen;
    if (inLen < totalLen) {
        // Not enough data available
        return 0;
    }
    // Initialized with expected IV from header
    int status = EVP_DecryptInit_ex(mContext.get(),
                                    mCipher,
                                    nullptr,
                                    reinterpret_cast<const uint8_t*>(&mAesKey),
                                    header.iv);
    if (status != 1) {
        return -1;
    }

    // Turn off padding as our data should be block-aligned from the encrypt()
    // call. Disabling padding will cause EVP_DecryptFinal_ex to fail if the
    // data is not block aligned.
    EVP_CIPHER_CTX_set_padding(mContext.get(), 0);

    int decryptedLen = 0;
    status = EVP_DecryptUpdate(mContext.get(), out, &decryptedLen,
                               in + sizeof(header), payloadLen);
    if (status != 1 || decryptedLen < 0) {
        return -1;
    }

    // Set expected tag from header
    status = EVP_CIPHER_CTX_ctrl(mContext.get(),
                                 EVP_CTRL_GCM_SET_TAG,
                                 sizeof(header.tag),
                                 const_cast<uint8_t*>(header.tag));
    if (status != 1) {
        return -1;
    }

    int len = 0;
    status = EVP_DecryptFinal_ex(mContext.get(), out + decryptedLen, &len);
    if (status != 1 || len != 0) {
        return -1;
    }
    // Return the length without the padding.
    return dataLen;
}

size_t Aes128Gcm::encryptedSize(size_t size) {
    // We need to account for block alignment of the encrypted data.
    // According to openssl.org/docs/man1.0.2/man3/EVP_EncryptUpdate.html,
    // "The amount of data written depends on the block alignment of the
    // encrypted data ..."
    // ".. the amount of data written may be anything from zero bytes to
    // (inl + cipher_block_size - 1) ..."
    const size_t cipher_block_size = EVP_CIPHER_block_size(mCipher);
    size_t padding = cipher_block_size - (size % cipher_block_size);
    if (padding != cipher_block_size) {
        size += padding;
    }
    return size + sizeof(Header);
}

size_t Aes128Gcm::decryptedSize(const uint8_t* encryptedData,
                                size_t encryptedSize) {
    if (encryptedSize < sizeof(Header)) {
        // Not enough data yet
        return 0;
    }
    auto header = reinterpret_cast<const Header*>(encryptedData);
    uint32_t length = ntohl(header->length);
    uint32_t payload_size = length + header->padding;
    if (encryptedSize < payload_size) {
        // There's enough data for the header but not enough data for the
        // payload. Indicate that there's not enough data for now.
        return 0;
    }
    // The decrypted data does not include the padding.
    return length;
}

}  // namespace pairing
}  // namespace adbwifi
