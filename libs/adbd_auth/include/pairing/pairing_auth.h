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

// PairingAuthCtx:
//
// These set of functions allow two parties to authenticate themselves to each
// other, using a common password |pswd|. This protocol is based on SPAKE2,
// which allows two parties to authenticate using a shared password, without
// actually exchanging the password out in the open.
//
// Once authticated, each party can generate pairing requests, which essentially
// contains the public certificate for the other to do what they want with it.
// In adb's case, we use the public certificate in a keystore.
//
// See tests/pairing/pairing_auth_test.cpp for example usage.

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
// the public key in bytes. Be sure buffer has at least
// |pairing_auth_max_key_size| bytes allocated.
int pairing_auth_our_public_key(PairingAuthCtx p, uint8_t* buffer);

// Registers the other party's public key, |theirKey| to the context. Call
// this before using createPairingRequest().
// this before using pairing_auth_encrypt() or pairing_auth_decrypt().
bool pairing_auth_register_their_key(PairingAuthCtx p,
                                     const uint8_t* theirKey,
                                     uint64_t theirKeySize);

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
