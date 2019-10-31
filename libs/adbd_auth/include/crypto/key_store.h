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

#include "crypto/public_key_header.h"

extern "C" {

typedef void* KeyStoreCtx;

// Initializes the KeyStoreCtx. If KeyStoreCtx is null, a separate thread
// will spawn and retry a certain amount of times, and will call |cb| with
// the KeyStoreCtx as null if the retries didn't succeed. Only need to call this
// once to initialize the KeyStoreCtx.
KeyStoreCtx keystore_init(const char* keystore_path,
                          void* opaque,
                          void (*cb)(KeyStoreCtx, void*));

// Writes the public key header for this device into |header|.
void keystore_public_key_header(KeyStoreCtx ctx,
                                PublicKeyHeader* header);

// Returns the key size iff the system's public key exists and writes it in
// |public_key|. Use |keystore_max_certificate_size| to allocate enough space
// for |public_key|. Returns zero otherwise.
uint32_t keystore_system_public_key(KeyStoreCtx ctx,
                                    char* public_key);
// Store the public key into the keystore. Returns false if it failed to save.
bool keystore_store_public_key(KeyStoreCtx ctx,
                               const PublicKeyHeader* header,
                               const char* public_key);

// Returns a "reasonable" size a certificate can be.
uint32_t keystore_max_certificate_size(KeyStoreCtx ctx);

// Returns the KeyStoreCtx instance. Be sure to initialize the context first
// with keystore_init(). Will return null if the context has not been created
// yet.
KeyStoreCtx keystore_get(void);

// Returns the file path to the keystore.
const char* keystore_file_path(KeyStoreCtx ctx);

// Returns the private key file path.
const char* keystore_priv_key_path(KeyStoreCtx ctx);

// Returns the public key file path.
const char* keystore_pub_key_path(KeyStoreCtx ctx);

} // extern "C"
