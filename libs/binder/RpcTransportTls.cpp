/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
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

#define LOG_TAG "RpcTransportTls"
#include <log/log.h>

#include <poll.h>

#include <binder/RpcTransportTls.h>

#define SHOULD_LOG_TLS_DETAIL false

#if SHOULD_LOG_TLS_DETAIL
#define LOG_TLS_DETAIL(...) ALOGI(__VA_ARGS__)
#else
#define LOG_TLS_DETAIL(...) ALOGV(__VA_ARGS__) // for type checking
#endif

#include <openssl/rand.h>
#include <openssl/ssl.h>

namespace android {
namespace {

constexpr const int kCertValidDays = 30;

bssl::UniquePtr<BIO> newSocketBio(android::base::borrowed_fd fd) {
    return bssl::UniquePtr<BIO>(BIO_new_socket(fd.get(), BIO_NOCLOSE));
}

bssl::UniquePtr<EVP_PKEY> makeKeyPairForSelfSignedCert() {
    bssl::UniquePtr<EC_KEY> ec_key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    if (!ec_key || !EC_KEY_generate_key(ec_key.get())) {
        ALOGE("Failed to generate key pair.");
        return nullptr;
    }
    bssl::UniquePtr<EVP_PKEY> evp_pkey(EVP_PKEY_new());
    if (!evp_pkey || !EVP_PKEY_assign_EC_KEY(evp_pkey.get(), ec_key.release())) {
        ALOGE("Failed to assign key pair.");
        return nullptr;
    }
    return evp_pkey;
}

bssl::UniquePtr<X509> makeSelfSignedCert(EVP_PKEY *evp_pkey, const int valid_days) {
    bssl::UniquePtr<X509> x509(X509_new());
    uint32_t serial;
    RAND_bytes(reinterpret_cast<uint8_t *>(&serial), sizeof(serial));
    ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), serial >> 1);
    X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(x509.get()), 60 * 60 * 24 * valid_days);

    X509_NAME *subject = X509_get_subject_name(x509.get());
    X509_NAME_add_entry_by_txt(subject, "C", MBSTRING_ASC, reinterpret_cast<const uint8_t *>("US"),
                               -1, -1, 0);
    X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC,
                               reinterpret_cast<const uint8_t *>("Android"), -1, -1, 0);
    X509_set_issuer_name(x509.get(), subject);

    if (!X509_set_pubkey(x509.get(), evp_pkey)) {
        ALOGE("Failed to set public key.");
        return nullptr;
    }
    if (!X509_sign(x509.get(), evp_pkey, EVP_sha256())) {
        ALOGE("Failed to sign certificate.");
        return nullptr;
    }
    return x509;
}

[[maybe_unused]] void sslDebugLog(const SSL *ssl, int type, int) {
    switch (type) {
        case SSL_CB_HANDSHAKE_START:
            LOG_TLS_DETAIL("Handshake started.");
            break;
        case SSL_CB_HANDSHAKE_DONE:
            LOG_TLS_DETAIL("Handshake done.");
            break;
        case SSL_CB_ACCEPT_LOOP:
            LOG_TLS_DETAIL("Handshake progress: %s", SSL_state_string_long(ssl));
            break;
    }
}

class RpcTransportTls : public RpcTransport {
public:
    RpcTransportTls(android::base::unique_fd socket, bssl::UniquePtr<SSL> ssl)
          : mSocket(std::move(socket)), mSsl(std::move(ssl)) {}
    int send(const void *buf, int size) override;
    int recv(void *buf, int size) override;
    int peek(void *buf, int size) override;
    bool pending() override;
    android::base::borrowed_fd pollSocket() const override { return mSocket; }

private:
    android::base::unique_fd mSocket;
    bssl::UniquePtr<SSL> mSsl;
};

int RpcTransportTls::send(const void *buf, int size) {
    while (true) {
        int ret = SSL_write(mSsl.get(), buf, size);
        if (ret <= 0) {
            int err = SSL_get_error(mSsl.get(), ret);
            if (err == SSL_ERROR_WANT_WRITE) {
                continue;
            }
            ALOGE("%s: SSL_write() error: %s", __PRETTY_FUNCTION__, SSL_error_description(err));
            return -1;
        }
        LOG_TLS_DETAIL("TLS: Sent %d bytes!", ret);
        return ret;
    }
}

int RpcTransportTls::recv(void *buf, int size) {
    while (true) {
        int ret = SSL_read(mSsl.get(), buf, size);
        if (ret < 0) {
            int err = SSL_get_error(mSsl.get(), ret);
            if (err == SSL_ERROR_WANT_READ) {
                continue;
            }
            ALOGE("%s: SSL_read() error: %s", __PRETTY_FUNCTION__, SSL_error_description(err));
            return -1;
        }
        LOG_TLS_DETAIL("TLS: Received %d bytes!", ret);
        return ret;
    }
}

int RpcTransportTls::peek(void *buf, int size) {
    while (true) {
        // SSL_peek() eventually calls socketRead() above, which doesn't specify MSG_DONTWAIT.
        // Emulate MSG_DONTWAIT by polling with no timeout.
        pollfd pfd{.fd = mSocket.get(), .events = POLLIN, .revents = 0};
        int pollRes = TEMP_FAILURE_RETRY(poll(&pfd, 1, 0 /* no timeout */));
        if (pollRes == -1) {
            ALOGE("%s: poll(): %s", __PRETTY_FUNCTION__, strerror(errno));
            return -1;
        }
        if (pfd.revents & POLLHUP) {
            ALOGE("%s: closed", __PRETTY_FUNCTION__);
            return -1;
        }
        if ((pfd.revents & POLLIN) == 0) {
            // No data pending on the raw socket FD. Check userspace buffer.
            if (!pending()) {
                // No data in userspace buffer either. ::recv(MSG_DONTWAIT) would return -1 with
                // EAGAIN or EWOULDBLOCK. Because RpcTransport::peek() is not required to set errno,
                // don't do it.
                LOG_TLS_DETAIL("%s: no data available for now.", __PRETTY_FUNCTION__);
                return -1;
            }
        }

        int ret = SSL_peek(mSsl.get(), buf, size);
        if (ret < 0) {
            int err = SSL_get_error(mSsl.get(), ret);
            if (err == SSL_ERROR_WANT_READ) {
                continue;
            }
            ALOGE("%s: SSL_peek() error: %s", __PRETTY_FUNCTION__, SSL_error_description(err));
            return -1;
        }
        LOG_TLS_DETAIL("TLS: Peeked %d bytes!", ret);
        return ret;
    }
}

bool RpcTransportTls::pending() {
    return static_cast<bool>(SSL_pending(mSsl.get()));
}

bssl::UniquePtr<SSL> connectAccept(SSL_CTX *ctx, android::base::borrowed_fd fd,
                                   decltype(&SSL_accept) fn, const char *fnString) {
    bssl::UniquePtr<SSL> ssl(SSL_new(ctx));
    if (ssl == nullptr) {
        ALOGE("SSL_new()");
        return nullptr;
    }
    bssl::UniquePtr<BIO> bio = newSocketBio(fd);
    if (bio == nullptr) {
        ALOGE("Unable to create BIO for fd %d", fd.get());
        return nullptr;
    }
    SSL_set_bio(ssl.get(), bio.get(), bio.release());
    if (int ret = fn(ssl.get()); ret == 0) {
        ALOGE("%s()", fnString);
        return nullptr;
    }
    return ssl;
}

class RpcTransportCtxTlsServer : public RpcTransportCtx {
public:
    static std::unique_ptr<RpcTransportCtxTlsServer> create();
    std::unique_ptr<RpcTransport> newTransport(android::base::unique_fd acceptedFd) const override;

private:
    bssl::UniquePtr<SSL_CTX> mCtx;
};

std::unique_ptr<RpcTransportCtxTlsServer> RpcTransportCtxTlsServer::create() {
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));

    // Server use self-signing cert
    auto evp_pkey = makeKeyPairForSelfSignedCert();
    if (evp_pkey == nullptr) {
        return nullptr;
    }
    auto cert = makeSelfSignedCert(evp_pkey.get(), kCertValidDays);
    if (cert == nullptr) {
        return nullptr;
    }
    if (!SSL_CTX_use_PrivateKey(ctx.get(), evp_pkey.get())) {
        ALOGE("Failed to set private key.");
        return nullptr;
    }
    if (!SSL_CTX_use_certificate(ctx.get(), cert.get())) {
        ALOGE("Failed to set certificate.");
        return nullptr;
    }
    if constexpr (SHOULD_LOG_TLS_DETAIL) { // NOLINT
        SSL_CTX_set_info_callback(ctx.get(), sslDebugLog);
    }

    // Require at least TLS 1.3
    if (!SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION)) {
        ALOGE("SSL_CTX_set_min_proto_version(1.3)");
        return nullptr;
    }

    auto rpcTransportTlsServerCtx = std::make_unique<RpcTransportCtxTlsServer>();
    rpcTransportTlsServerCtx->mCtx = std::move(ctx);

    return rpcTransportTlsServerCtx;
}
std::unique_ptr<RpcTransport> RpcTransportCtxTlsServer::newTransport(
        android::base::unique_fd acceptedFd) const {
    auto ssl = connectAccept(mCtx.get(), acceptedFd, &SSL_accept, "SSL_accept");
    return std::make_unique<RpcTransportTls>(std::move(acceptedFd), std::move(ssl));
}

class RpcTransportCtxTlsClient : public RpcTransportCtx {
public:
    static std::unique_ptr<RpcTransportCtxTlsClient> create();
    std::unique_ptr<RpcTransport> newTransport(android::base::unique_fd connectedFd) const override;

private:
    bssl::UniquePtr<SSL_CTX> mCtx;
};

std::unique_ptr<RpcTransportCtxTlsClient> RpcTransportCtxTlsClient::create() {
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));

    if constexpr (SHOULD_LOG_TLS_DETAIL) { // NOLINT
        SSL_CTX_set_info_callback(ctx.get(), sslDebugLog);
    }

    // Require at least TLS 1.3
    if (!SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION)) {
        ALOGE("SSL_CTX_set_min_proto_version(1.3)");
        return nullptr;
    }

    auto rpcTransportTlsClientCtx = std::make_unique<RpcTransportCtxTlsClient>();
    rpcTransportTlsClientCtx->mCtx = std::move(ctx);

    return rpcTransportTlsClientCtx;
}
std::unique_ptr<RpcTransport> RpcTransportCtxTlsClient::newTransport(
        android::base::unique_fd connectedFd) const {
    // TODO(b/190868302): server should send certificate in a different channel, and client
    //  should verify it here.
    auto ssl = connectAccept(mCtx.get(), connectedFd, &SSL_connect, "SSL_connect");
    return std::make_unique<RpcTransportTls>(std::move(connectedFd), std::move(ssl));
}

} // namespace

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryTls::newServerCtx() const {
    return android::RpcTransportCtxTlsServer::create();
}

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryTls::newClientCtx() const {
    return android::RpcTransportCtxTlsClient::create();
}

bool RpcTransportCtxFactoryTls::tlsEnabled() const {
    return true;
}

} // namespace android
