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

#include "crypto/public_key_header.h"

extern "C" {

typedef void* PairingAuthCtx;

enum PairingRole {
    Client = 0,
    Server = 1,
};

// Constructs a new PairingAuthCtx with the given |role| and shared password,
// |pswd|. Returns null if context creation failed.
PairingAuthCtx pairing_auth_new_ctx(PairingRole role,
                                    const uint8_t* pswd,
                                    uint64_t pswdSize);
// Deletes the PairingAuthCtx.
void pairing_auth_delete_ctx(PairingAuthCtx ctx);

// Returns the maximum size a key can be.
uint32_t pairing_auth_max_key_size(PairingAuthCtx ctx);

// Returns our public key for this context in |buffer| and returns the size of
// the public key in bytes. Be sure buffer has at least |kMaxKeySize| bytes
// allocated.
int pairing_auth_our_public_key(PairingAuthCtx p, uint8_t* buffer);
// Registers the other party's public key, |theirKey| to the context. Call
// this before using createPairingRequest().
// this before using pairing_auth_encrypt() or pairing_auth_decrypt().
bool pairing_auth_register_their_key(PairingAuthCtx p,
                                     const uint8_t* theirKey,
                                     uint64_t theirKeySize);
//// Returns the size needed to decrypt the |encrypted| data. Call this prior to
//// calling pairing_auth_decrypt() to allocate enough space for your buffer.
//// This may return zero if unable to determine the size needed.
//uint64_t pairing_auth_decrypted_size(PairingAuthCtx p,
//                                     const uint8_t* encrypted,
//                                     uint64_t sz);
//// Decrypt the |msg| and write the decrypted message in |out|, with its size in
//// |outSize|. The return will be false if decryption failed.
//bool pairing_auth_decrypt(PairingAuthCtx p,
//                          const uint8_t* msg,
//                          uint64_t msgSize,
//                          uint8_t* out,
//                          uint64_t* outSize);
//// Returns the size needed to encrypt |dataSize| amount of data. Call this prior to
//// calling pairing_auth_encrypt() to allocate enough space for your buffer.
//// This may return zero if unable to determine the size needed.
//uint64_t pairing_auth_encrypted_size(PairingAuthCtx p,
//                                     uint64_t dataSize);
//// Encrypt the |msg| and writes the encrypted message in |out|, with its size in
//// |outSize|. The return will be false if encryption failed.
//bool pairing_auth_encrypt(PairingAuthCtx p,
//                          const uint8_t* msg,
//                          uint64_t msgSize,
//                          uint8_t* out,
//                          uint64_t* outSize);

// Returns the max size needed to construct a pairing request data packet.
uint32_t pairing_auth_request_max_size();
// Creates a pairing request packet from |header| and |public_key| and stores it in
// |pkt|. The size will be in |pktSize|. On failure, this will return false.
bool pairing_auth_create_request(PairingAuthCtx ctx,
                                 const PublicKeyHeader* header,
                                 const char* public_key,
                                 uint8_t* pkt,
                                 uint32_t* pktSize);
// Reads the pairing request packet in |pkt|. Returns true if successfully able
// to parse the packet, with |out_header| and |out_public_key| filled in, with the
// |out_public_key| size equaling the |out_header->payload|. Returns false otherwise.
// To be safe, make sure has enough space (use keystore_max_certificate_size()) to
// write into.
bool pairing_auth_parse_request(PairingAuthCtx ctx,
                                const uint8_t* pkt,
                                uint32_t pktSize,
                                PublicKeyHeader* out_header,
                                char* out_public_key);


}  // extern "C"
