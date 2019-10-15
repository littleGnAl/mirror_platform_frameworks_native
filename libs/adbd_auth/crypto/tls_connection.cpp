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

    // Add a known certificate to SSL connection.
    bool addKnownCertificate(std::string_view cert);
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
    static bssl::UniquePtr<CRYPTO_BUFFER> bufferFromPEM(const char* pem);
    static bssl::UniquePtr<X509> x509FromBuffer(
            bssl::UniquePtr<CRYPTO_BUFFER> buffer);
    void invalidate();
    bool m_is_server_;
    bssl::UniquePtr<SSL_CTX> m_ssl_ctx_;
    bssl::UniquePtr<SSL> m_ssl_;
    std::vector<bssl::UniquePtr<X509>> m_known_certificates_;
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

// static
bssl::UniquePtr<CRYPTO_BUFFER> TlsConnection::bufferFromPEM(const char* pem) {
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem, strlen(pem)));
    char* name = nullptr;
    char* header = nullptr;
    uint8_t* data = nullptr;
    long data_len = 0;

    if (!PEM_read_bio(bio.get(),
                      &name,
                      &header,
                      &data,
                      &data_len)) {
        LOG(ERROR) << "Failed to read certificate";
        return nullptr;
    }
    OPENSSL_free(name);
    OPENSSL_free(header);

    auto ret = bssl::UniquePtr<CRYPTO_BUFFER>(
            CRYPTO_BUFFER_new(data, data_len, nullptr));
    OPENSSL_free(data);
    return ret;
}

// static
bssl::UniquePtr<X509> TlsConnection::x509FromBuffer(
        bssl::UniquePtr<CRYPTO_BUFFER> buffer) {
    if (!buffer) {
        return nullptr;
    }
    const uint8_t* derp = CRYPTO_BUFFER_data(buffer.get());
    return bssl::UniquePtr<X509>(
            d2i_X509(nullptr, &derp, CRYPTO_BUFFER_len(buffer.get())));
}

bool TlsConnection::addKnownCertificate(std::string_view cert) {
    if (cert.empty()) {
        LOG(ERROR) << "Certificate is empty";
        return false;
    }
    // Create X509 buffer from the certificate string
    auto buf = x509FromBuffer(bufferFromPEM(cert.data()));
    if (buf == nullptr) {
        LOG(ERROR) << "Failed to create a X509 buffer for the certificate.";
        return false;
    }
    m_known_certificates_.push_back(std::move(buf));
    return true;
}

bool TlsConnection::doHandshake(int fd,
                                const char* cert_file,
                                const char* priv_key_file) {
    int err = -1;
    LOG(INFO) << "Starting adbwifi tls handshake";
    m_ssl_ctx_.reset(SSL_CTX_new(m_is_server_ ?
                                 TLSv1_2_server_method() :
                                 TLSv1_2_client_method()));

    // Register every certificate in our keystore. This will restrict
    // connnections to only these known certificates.
    for (auto const& cert : m_known_certificates_) {
        if (X509_STORE_add_cert(SSL_CTX_get_cert_store(m_ssl_ctx_.get()),
                                cert.get()) == 0) {
            LOG(ERROR) << "Unable to add certificates into the X509_STORE";
            return false;
        }
    }

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

    SSL_CTX_set_verify(m_ssl_ctx_.get(),
                       SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                       nullptr);

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

bool tls_connection_add_known_certificate(TlsConnectionCtx ctx,
                                          const char* data,
                                          size_t size) {
    CHECK(ctx);
    if (size == 0) {
        return false;
    }
    auto* p = reinterpret_cast<TlsConnection*>(ctx);
    return p->addKnownCertificate(std::string_view(data, size));
}
