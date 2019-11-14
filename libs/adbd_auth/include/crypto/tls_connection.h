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

extern "C" {

typedef void* TlsConnectionCtx;

// Create a new TLS connection.
TlsConnectionCtx tls_connection_new_ctx(bool is_server);

// Destroy the TLS connection.
void tls_connection_delete_ctx(TlsConnectionCtx ctx);

// Perform a TLS handshake with the given connection in |fd|, the public
// certificate file |cert_file|, and the private key file |priv_key_file|.
bool tls_connection_handshake(TlsConnectionCtx ctx,
                              int fd,
                              const char* cert_file,
                              const char* priv_key_file);

// Writes all |size| bytes out. Returns true if all bytes were written,
// false otherwise. If |size| is zero, immediately returns true.
bool tls_connection_write_fully(TlsConnectionCtx ctx,
                                const void* data,
                                int size);

// Reads bytes out. Returns true if all bytes were read, false otherwise.
// The data will be written to |data|. If |size| is zero, imeediately returns
// true.
bool tls_connection_read_fully(TlsConnectionCtx ctx,
                               void* data,
                               int size);

// Add a known certificate to the connection. You must add all known
// certificates prior to initiating the handshake, or the handshake will fail.
// Returns true if successfully added the certificate, false otherwise.
bool tls_connection_add_known_certificate(TlsConnectionCtx ctx,
                                          const char* data,
                                          size_t size);
}  // extern "C"
