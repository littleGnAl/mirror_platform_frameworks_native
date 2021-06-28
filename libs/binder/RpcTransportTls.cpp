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

#include <openssl/rand.h>
#include <openssl/ssl.h>

#include <binder/RpcTransportTls.h>

#include "FdTrigger.h"
#include "RpcState.h"

#define SHOULD_LOG_TLS_DETAIL false

#if SHOULD_LOG_TLS_DETAIL
#define LOG_TLS_DETAIL(...) ALOGI(__VA_ARGS__)
#else
#define LOG_TLS_DETAIL(...) ALOGV(__VA_ARGS__) // for type checking
#endif

#define TEST_AND_RETURN(value, expr)            \
    do {                                        \
        if (!(expr)) {                          \
            ALOGE("Failed to call: %s", #expr); \
            return value;                       \
        }                                       \
    } while (0)

using android::base::ErrnoError;
using android::base::Error;
using android::base::Result;

namespace android {
namespace {

constexpr const int kCertValidDays = 30;

bssl::UniquePtr<BIO> newSocketBio(android::base::borrowed_fd fd) {
    return bssl::UniquePtr<BIO>(BIO_new_socket(fd.get(), BIO_NOCLOSE));
}

bssl::UniquePtr<EVP_PKEY> makeKeyPairForSelfSignedCert() {
    bssl::UniquePtr<EC_KEY> ec_key(EC_KEY_new_by_curve_name(NID_X9_62_prime256v1));
    if (ec_key == nullptr || !EC_KEY_generate_key(ec_key.get())) {
        ALOGE("Failed to generate key pair.");
        return nullptr;
    }
    bssl::UniquePtr<EVP_PKEY> evp_pkey(EVP_PKEY_new());
    // Use set1 instead of assign to avoid leaking ec_key when assign fails. set1 increments
    // the refcount of the ec_key, so it is okay to release it at the end of this function.
    if (evp_pkey == nullptr || !EVP_PKEY_set1_EC_KEY(evp_pkey.get(), ec_key.get())) {
        ALOGE("Failed to assign key pair.");
        return nullptr;
    }
    return evp_pkey;
}

bssl::UniquePtr<X509> makeSelfSignedCert(EVP_PKEY *evp_pkey, const int valid_days) {
    bssl::UniquePtr<X509> x509(X509_new());
    bssl::UniquePtr<BIGNUM> serial(BN_new());
    bssl::UniquePtr<BIGNUM> serial_limit(BN_new());
    TEST_AND_RETURN(nullptr, BN_lshift(serial_limit.get(), BN_value_one(), 128));
    TEST_AND_RETURN(nullptr, BN_rand_range(serial.get(), serial_limit.get()));
    TEST_AND_RETURN(nullptr, BN_to_ASN1_INTEGER(serial.get(), X509_get_serialNumber(x509.get())));
    TEST_AND_RETURN(nullptr, X509_gmtime_adj(X509_getm_notBefore(x509.get()), 0));
    TEST_AND_RETURN(nullptr,
                    X509_gmtime_adj(X509_getm_notAfter(x509.get()), 60 * 60 * 24 * valid_days));

    X509_NAME *subject = X509_get_subject_name(x509.get());
    TEST_AND_RETURN(nullptr,
                    X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC,
                                               reinterpret_cast<const uint8_t *>("Android"), -1, -1,
                                               0));
    TEST_AND_RETURN(nullptr,
                    X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC,
                                               reinterpret_cast<const uint8_t *>("BinderRPC"), -1,
                                               -1, 0));
    TEST_AND_RETURN(nullptr, X509_set_issuer_name(x509.get(), subject));

    TEST_AND_RETURN(nullptr, X509_set_pubkey(x509.get(), evp_pkey));
    TEST_AND_RETURN(nullptr, X509_sign(x509.get(), evp_pkey, EVP_sha256()));
    return x509;
}

[[maybe_unused]] void sslDebugLog(const SSL *ssl, int type, int value) {
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
        default:
            LOG_TLS_DETAIL("SSL Debug Log: type = %d, value = %d", type, value);
            break;
    }
}

class RpcTransportTls : public RpcTransport {
public:
    RpcTransportTls(android::base::unique_fd socket, bssl::UniquePtr<SSL> ssl)
          : mSocket(std::move(socket)), mSsl(std::move(ssl)) {}
    Result<size_t> peek(void *buf, size_t size) override;
    status_t interruptableWriteFully(FdTrigger *fdTrigger, const void *buf, size_t size) override;
    status_t interruptableReadFully(FdTrigger *fdTrigger, void *buf, size_t size) override;

private:
    android::base::unique_fd mSocket;
    bssl::UniquePtr<SSL> mSsl;

    Result<size_t> send(const void *buf, size_t size);
    Result<size_t> recv(void *buf, size_t size);
};

// Error code is SSL error.
Result<size_t> RpcTransportTls::send(const void *buf, size_t size) {
    size_t todo = std::min<size_t>(size, std::numeric_limits<int>::max());
    int ret = SSL_write(mSsl.get(), buf, static_cast<int>(todo));
    if (ret < 0) {
        int err = SSL_get_error(mSsl.get(), ret);
        return Error(err);
    }
    LOG_TLS_DETAIL("TLS: Sent %d bytes!", ret);
    return ret;
}

// Error code is SSL error.
Result<size_t> RpcTransportTls::recv(void *buf, size_t size) {
    size_t todo = std::min<size_t>(size, std::numeric_limits<int>::max());
    int ret = SSL_read(mSsl.get(), buf, static_cast<int>(todo));
    if (ret < 0) {
        int err = SSL_get_error(mSsl.get(), ret);
        return Error(err);
    }
    LOG_TLS_DETAIL("TLS: Received %d bytes!", ret);
    return ret;
}

// Error code is errno.
Result<size_t> RpcTransportTls::peek(void *buf, size_t size) {
    size_t todo = std::min<size_t>(size, std::numeric_limits<int>::max());
    int ret = SSL_peek(mSsl.get(), buf, static_cast<int>(todo));
    if (ret < 0) {
        int err = SSL_get_error(mSsl.get(), ret);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            // Seen EAGAIN / EWOULDBLOCK on recv(2) / send(2).
            // Like RpcTransportRaw::peek(), don't handle it here.
            return Error(EWOULDBLOCK) << "SSL_peek(): " << SSL_error_description(err);
        }
        return Error() << "SSL_peek(): " << SSL_error_description(err);
    }
    LOG_TLS_DETAIL("TLS: Peeked %d bytes!", ret);
    return ret;
}
status_t RpcTransportTls::interruptableWriteFully(FdTrigger *fdTrigger, const void *data,
                                                  size_t size) {
    const uint8_t *buffer = reinterpret_cast<const uint8_t *>(data);
    const uint8_t *end = buffer + size;

    MAYBE_WAIT_IN_FLAKE_MODE;

    int event = POLLIN | POLLOUT;
    status_t status;
    while ((status = fdTrigger->triggerablePoll(mSocket.get(), event)) == OK) {
        auto writeSize = this->send(buffer, end - buffer);
        if (!writeSize.ok()) {
            LOG_RPC_DETAIL("SSL_write(): %s", SSL_error_description(writeSize.error().code()));
            switch (writeSize.error().code()) {
                case SSL_ERROR_WANT_READ:
                    event = POLLIN;
                    continue; // poll again
                case SSL_ERROR_WANT_WRITE:
                    event = POLLOUT;
                    continue; // poll again
                default:
                    return UNKNOWN_ERROR;
            }
        }

        // This assumes that SSL_write() only returns 0 on EOF.
        // https://crbug.com/466303
        if (*writeSize == 0) return DEAD_OBJECT;

        buffer += *writeSize;
        if (buffer == end) return OK;
    }
    return status;
}

status_t RpcTransportTls::interruptableReadFully(FdTrigger *fdTrigger, void *data, size_t size) {
    uint8_t *buffer = reinterpret_cast<uint8_t *>(data);
    uint8_t *end = buffer + size;

    MAYBE_WAIT_IN_FLAKE_MODE;

    int event = POLLIN | POLLOUT;
    status_t status;
    while ((status = fdTrigger->triggerablePoll(mSocket.get(), event)) == OK) {
        auto readSize = this->recv(buffer, end - buffer);
        if (!readSize.ok()) {
            LOG_RPC_DETAIL("SSL_read(): %s", SSL_error_description(readSize.error().code()));
            switch (readSize.error().code()) {
                case SSL_ERROR_WANT_READ:
                    event = POLLIN;
                    continue; // poll again
                case SSL_ERROR_WANT_WRITE:
                    event = POLLOUT;
                    continue; // poll again
                default:
                    return UNKNOWN_ERROR;
            }
        }

        // This assumes that SSL_read() only returns 0 on EOF.
        // https://crbug.com/466303
        if (*readSize == 0) return DEAD_OBJECT;

        buffer += *readSize;
        if (buffer == end) return OK;
    }
    return status;
}

bool setFdAndDoHandshake(SSL *ssl, android::base::borrowed_fd fd, FdTrigger *fdTrigger) {
    bssl::UniquePtr<BIO> bio = newSocketBio(fd);
    TEST_AND_RETURN(false, bio != nullptr);
    SSL_set_bio(ssl, bio.get(), bio.release());

    MAYBE_WAIT_IN_FLAKE_MODE;

    int event = POLLIN | POLLOUT;
    status_t status;
    while ((status = fdTrigger->triggerablePoll(fd, event)) == OK) {
        int ret = SSL_do_handshake(ssl);
        if (ret > 0) {
            return true;
        }
        int err = SSL_get_error(ssl, ret);
        LOG_TLS_DETAIL("SSL_do_handshake(): %s", SSL_error_description(err));
        switch (err) {
            case SSL_ERROR_WANT_READ:
                event = POLLIN;
                continue; // poll again
            case SSL_ERROR_WANT_WRITE:
                event = POLLOUT;
                continue; // poll again
            default:
                ALOGE("SSL_do_handshake(): %s", SSL_error_description(err));
                return false;
        }
    }
    ALOGE("%s: cancelled because shutdown triggered: %s", __PRETTY_FUNCTION__,
          statusToString(status).c_str());
    return false;
}

class RpcTransportCtxTlsServer : public RpcTransportCtx {
public:
    static std::unique_ptr<RpcTransportCtxTlsServer> create();
    std::unique_ptr<RpcTransport> newTransport(android::base::unique_fd acceptedFd,
                                               FdTrigger *fdTrigger) const override;

private:
    bssl::UniquePtr<SSL_CTX> mCtx;
};

std::unique_ptr<RpcTransportCtxTlsServer> RpcTransportCtxTlsServer::create() {
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));

    // Server use self-signing cert
    auto evp_pkey = makeKeyPairForSelfSignedCert();
    TEST_AND_RETURN(nullptr, evp_pkey != nullptr);
    auto cert = makeSelfSignedCert(evp_pkey.get(), kCertValidDays);
    TEST_AND_RETURN(nullptr, cert != nullptr);
    TEST_AND_RETURN(nullptr, SSL_CTX_use_PrivateKey(ctx.get(), evp_pkey.get()));
    TEST_AND_RETURN(nullptr, SSL_CTX_use_certificate(ctx.get(), cert.get()));
    // Require at least TLS 1.3
    TEST_AND_RETURN(nullptr, SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION));

    if constexpr (SHOULD_LOG_TLS_DETAIL) { // NOLINT
        SSL_CTX_set_info_callback(ctx.get(), sslDebugLog);
    }

    auto rpcTransportTlsServerCtx = std::make_unique<RpcTransportCtxTlsServer>();
    rpcTransportTlsServerCtx->mCtx = std::move(ctx);
    return rpcTransportTlsServerCtx;
}

std::unique_ptr<RpcTransport> RpcTransportCtxTlsServer::newTransport(
        android::base::unique_fd acceptedFd, FdTrigger *fdTrigger) const {
    bssl::UniquePtr<SSL> ssl(SSL_new(mCtx.get()));
    TEST_AND_RETURN(nullptr, ssl != nullptr);
    SSL_set_accept_state(ssl.get());
    TEST_AND_RETURN(nullptr, setFdAndDoHandshake(ssl.get(), acceptedFd, fdTrigger));
    return std::make_unique<RpcTransportTls>(std::move(acceptedFd), std::move(ssl));
}

class RpcTransportCtxTlsClient : public RpcTransportCtx {
public:
    static std::unique_ptr<RpcTransportCtxTlsClient> create();
    std::unique_ptr<RpcTransport> newTransport(android::base::unique_fd connectedFd,
                                               FdTrigger *fdTrigger) const override;

private:
    bssl::UniquePtr<SSL_CTX> mCtx;
};

std::unique_ptr<RpcTransportCtxTlsClient> RpcTransportCtxTlsClient::create() {
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));

    // Require at least TLS 1.3
    TEST_AND_RETURN(nullptr, SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION));

    if constexpr (SHOULD_LOG_TLS_DETAIL) { // NOLINT
        SSL_CTX_set_info_callback(ctx.get(), sslDebugLog);
    }

    auto rpcTransportTlsClientCtx = std::make_unique<RpcTransportCtxTlsClient>();
    rpcTransportTlsClientCtx->mCtx = std::move(ctx);
    return rpcTransportTlsClientCtx;
}

std::unique_ptr<RpcTransport> RpcTransportCtxTlsClient::newTransport(
        android::base::unique_fd connectedFd, FdTrigger *fdTrigger) const {
    // No certificate verification configured because we only want passively-secure connections.
    // TODO(b/195166979): server should send certificate in a different channel, and client
    //  should verify it here.
    bssl::UniquePtr<SSL> ssl(SSL_new(mCtx.get()));
    TEST_AND_RETURN(nullptr, ssl != nullptr);
    SSL_set_connect_state(ssl.get());
    TEST_AND_RETURN(nullptr, setFdAndDoHandshake(ssl.get(), connectedFd, fdTrigger));
    if (ssl == nullptr) return nullptr;
    return std::make_unique<RpcTransportTls>(std::move(connectedFd), std::move(ssl));
}

} // namespace

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryTls::newServerCtx() const {
    return android::RpcTransportCtxTlsServer::create();
}

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryTls::newClientCtx() const {
    return android::RpcTransportCtxTlsClient::create();
}

const char *RpcTransportCtxFactoryTls::toCString() const {
    return "tls";
}

std::unique_ptr<RpcTransportCtxFactory> RpcTransportCtxFactoryTls::make() {
    return std::unique_ptr<RpcTransportCtxFactoryTls>(new RpcTransportCtxFactoryTls());
}

} // namespace android
