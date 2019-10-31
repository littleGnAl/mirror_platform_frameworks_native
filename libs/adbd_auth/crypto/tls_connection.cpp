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

#include "crypto/tls_connection.h"

#include <vector>

#include <android-base/logging.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

namespace {

class TlsConnection {
public:
    explicit TlsConnection(bool is_server);

    // starts the handshake process with the given fd.
    bool doHandshake(int fd,
                     const char* cert_file,
                     const char* priv_key_file);
    // Reads |size| bytes and returns the data. The returned data has either
    // size |size| or zero, in which case the read failed.
    std::vector<uint8_t> readFully(int size);
    // Writes |size| bytes. Returns true if all |size| bytes were read.
    // Returns false otherwise.
    bool writeFully(std::string_view data);
private:
    void invalidate();
    bool m_is_server_;
    bssl::UniquePtr<SSL_CTX> m_ssl_ctx_;
    bssl::UniquePtr<SSL> m_ssl_;
};  // TlsHandshake

TlsConnection::TlsConnection(bool is_server) :
    m_is_server_(is_server) {
    LOG(INFO) << "Initializing adbwifi TlsConnection (is_server=" << is_server << ")";
    // Init SSL library. Registers all available SSL/TLS ciphers and digests.
    SSL_library_init();
    SSL_load_error_strings();
}

const char* SSLErrorString() {
    auto sslerr = ERR_get_error();
    return ERR_reason_error_string(sslerr);
}

bool TlsConnection::doHandshake(int fd,
                                const char* cert_file,
                                const char* priv_key_file) {
    int err = -1;
    LOG(INFO) << "Starting adbwifi tls handshake";
    m_ssl_ctx_.reset(SSL_CTX_new(m_is_server_ ?
                                 TLSv1_2_server_method() :
                                 TLSv1_2_client_method()));

    // Set automatic curve selection for |m_ssl_ctx_|. It will select the
    // highest preference curve for the ECDH temp keys during key exchange.
    if (!SSL_CTX_set_ecdh_auto(m_ssl_ctx_.get(), 1)) {
        LOG(ERROR) << "SSL_CTX-set_ecdh_auto() failed";
        invalidate();
        return false;
    }

    // Register our certificate file. The chain file must be PEM format.
    if (!(err = SSL_CTX_use_certificate_chain_file(m_ssl_ctx_.get(),
                                                   cert_file))) {
        LOG(ERROR) << "Unable to use certificate chain file (file=" << cert_file << ") ["
                   << SSLErrorString() << "]";
        invalidate();
        return false;
    }
    // Register our private key file.
    if (!(err = SSL_CTX_use_PrivateKey_file(m_ssl_ctx_.get(),
                                            priv_key_file,
                                            SSL_FILETYPE_PEM))) {
        LOG(ERROR) << "Unable to use private key file (file=" << priv_key_file << ") ["
                   << SSLErrorString() << "]";
        invalidate();
        return false;
    }

    // TODO: add a callback parameter to verify the certificate against the
    // keystore. Since both ends have a keystore, both sides should make this
    // verification.
    SSL_CTX_set_verify(m_ssl_ctx_.get(),
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       nullptr);
    SSL_CTX_set_cert_verify_callback(
        m_ssl_ctx_.get(),
        [](X509_STORE_CTX* /* store */, void* /* arg */) -> int {
            // TODO: add the certificate verification here. On failure, return
            // 0. On success, return 1.
            return 1;
        }, nullptr);

    // Okay! Let's try to do the handshake!
    m_ssl_.reset(SSL_new(m_ssl_ctx_.get()));
    SSL_set_fd(m_ssl_.get(), fd);
    err = m_is_server_ ?
            SSL_accept(m_ssl_.get()) : SSL_connect(m_ssl_.get());
    if (err != 1) {
        LOG(ERROR) << "Handshake failed in SSL_accept/SSL_connect ["
                   << SSLErrorString() << "]";
        invalidate();
        return false;
    }

    LOG(INFO) << "Handshake succeeded.";
    return true;
}

void TlsConnection::invalidate() {
    m_ssl_.reset();
    m_ssl_ctx_.reset();
}

std::vector<uint8_t> TlsConnection::readFully(int size) {
    CHECK_GT(size, 0);
    if (!m_ssl_) {
        LOG(ERROR) << "Tried to read on a null SSL connection";
        return {};
    }

//    LOG(INFO) << "Trying to SSL_read " << size << " bytes";
    std::vector<uint8_t> buf(size);
    size_t offset = 0;
    while (size > 0) {
        int bytes_read = SSL_read(m_ssl_.get(), buf.data() + offset, size);
        if (bytes_read <= 0) {
            LOG(WARNING) << "SSL_read failed [" << SSLErrorString() << "]";
            return {};
        }
        size -= bytes_read;
        offset += bytes_read;
    }
//    LOG(INFO) << "Successfully SSL_read " << offset << " bytes.";
    return buf;
}

bool TlsConnection::writeFully(std::string_view data) {
    CHECK(!data.empty());
    if (!m_ssl_) {
        LOG(ERROR) << "Tried to read on a null SSL connection";
        return false;
    }

//    LOG(INFO) << "Trying to SSL_write " << data.size() << " bytes";
    size_t offset = 0;
    int size = data.size();
    while (size > 0) {
        int bytes_out = SSL_write(m_ssl_.get(), data.data() + offset, size);
        if (bytes_out <= 0) {
            LOG(WARNING) << "SSL_write failed [" << SSLErrorString() << "]";
            return false;
        }
        size -= bytes_out;
        offset += bytes_out;
    }
//    LOG(INFO) << "Successfully SSL_write " << offset << " bytes.";
    return true;
}

}  // namespace

TlsConnectionCtx tls_connection_new_ctx(bool is_server) {
    return static_cast<void*>(new TlsConnection(is_server));
}

void tls_connection_delete_ctx(TlsConnectionCtx ctx) {
    auto* p = reinterpret_cast<TlsConnection*>(ctx);
    if (p != nullptr) {
        delete p;
    }
}

bool tls_connection_handshake(TlsConnectionCtx ctx,
                              int fd,
                              const char* cert_file,
                              const char* priv_key_file) {
    CHECK(ctx);
    auto* p = reinterpret_cast<TlsConnection*>(ctx);
    return p->doHandshake(fd, cert_file, priv_key_file);
}

bool tls_connection_write_fully(TlsConnectionCtx ctx,
                                const void* data,
                                int size) {
    CHECK(ctx);
    if (size == 0) {
        return true;
    }

    auto* p = reinterpret_cast<TlsConnection*>(ctx);
    return p->writeFully(std::string_view(
            reinterpret_cast<const char*>(data), size));
}

bool tls_connection_read_fully(TlsConnectionCtx ctx,
                               void* data,
                               int size) {
    CHECK(ctx);
    if (size == 0) {
        return true;
    }

    auto* p = reinterpret_cast<TlsConnection*>(ctx);
    auto ret = p->readFully(size);
    if (ret.empty()) {
        return false;
    }
    memcpy(data, ret.data(), size);
    return true;
}
