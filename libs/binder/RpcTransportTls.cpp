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

// Implement BIO for socket that ignores SIGPIPE.
int socketNew(BIO *bio) {
    BIO_set_data(bio, reinterpret_cast<void *>(-1));
    BIO_set_init(bio, 0);
    return 1;
}
int socketFree(BIO *bio) {
    if (bio == nullptr) return 0;
    return 1;
}
int socketRead(BIO *bio, char *buf, int size) {
    if (buf == nullptr) return 0;
    android::base::borrowed_fd fd(static_cast<int>(reinterpret_cast<intptr_t>(BIO_get_data(bio))));
    int ret = TEMP_FAILURE_RETRY(::recv(fd.get(), buf, size, MSG_NOSIGNAL));
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        BIO_set_retry_read(bio);
    } else {
        BIO_clear_retry_flags(bio);
    }
    return ret;
}

int socketWrite(BIO *bio, const char *buf, int size) {
    android::base::borrowed_fd fd(static_cast<int>(reinterpret_cast<intptr_t>(BIO_get_data(bio))));
    int ret = TEMP_FAILURE_RETRY(::send(fd.get(), buf, size, MSG_NOSIGNAL));
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        BIO_set_retry_write(bio);
    } else {
        BIO_clear_retry_flags(bio);
    }
    return ret;
}

long socketCtrl(BIO *bio, int cmd, long num, void *) { // NOLINT
    android::base::borrowed_fd fd(static_cast<int>(reinterpret_cast<intptr_t>(BIO_get_data(bio))));
    switch (cmd) {
        case BIO_CTRL_FLUSH:
            return 1;
        default:
            LOG_ALWAYS_FATAL("sockCtrl(fd=%d, %d, %ld)", fd.get(), cmd, num);
            return 0;
    }
}

bssl::UniquePtr<BIO> newSocketBio(android::base::borrowed_fd fd) {
    static const BIO_METHOD *gMethods = ([] {
        auto methods = BIO_meth_new(BIO_get_new_index(), "socket_no_signal");
        LOG_ALWAYS_FATAL_IF(0 == BIO_meth_set_write(methods, socketWrite), "BIO_meth_set_write");
        LOG_ALWAYS_FATAL_IF(0 == BIO_meth_set_read(methods, socketRead), "BIO_meth_set_read");
        LOG_ALWAYS_FATAL_IF(0 == BIO_meth_set_ctrl(methods, socketCtrl), "BIO_meth_set_ctrl");
        LOG_ALWAYS_FATAL_IF(0 == BIO_meth_set_create(methods, socketNew), "BIO_meth_set_create");
        LOG_ALWAYS_FATAL_IF(0 == BIO_meth_set_destroy(methods, socketFree), "BIO_meth_set_destroy");
        return methods;
    })();
    bssl::UniquePtr<BIO> ret(BIO_new(gMethods));
    if (ret == nullptr) return nullptr;
    BIO_set_data(ret.get(), reinterpret_cast<void *>(fd.get()));
    BIO_set_init(ret.get(), 1);
    return ret;
}

struct KeyPair {
    bssl::UniquePtr<EC_KEY> ec_key;
    bssl::UniquePtr<EVP_PKEY> evp_pkey;
};

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
    TEST_AND_RETURN(nullptr, X509_gmtime_adj(X509_get_notBefore(x509.get()), 0));
    TEST_AND_RETURN(nullptr,
                    X509_gmtime_adj(X509_get_notAfter(x509.get()), 60 * 60 * 24 * valid_days));

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
    Result<size_t> send(const void *buf, size_t size) override;
    Result<size_t> recv(void *buf, size_t size) override;
    Result<size_t> peek(void *buf, size_t size) override;
    bool pending() override;
    android::base::borrowed_fd pollSocket() const override { return mSocket; }

private:
    android::base::unique_fd mSocket;
    bssl::UniquePtr<SSL> mSsl;
};

Result<size_t> RpcTransportTls::send(const void *buf, size_t size) {
    size_t todo = std::min<size_t>(size, std::numeric_limits<int>::max());
    int ret = SSL_write(mSsl.get(), buf, static_cast<int>(todo));
    if (ret <= 0) {
        int err = SSL_get_error(mSsl.get(), ret);
        if (err == SSL_ERROR_WANT_WRITE) {
            // SSL_ERROR_WANT_WRITE only happens when the socket is non-blocking. This is similar to
            // EAGAIN / EWOULDBLOCK on send(2). Like RpcTransportRaw::send(), don't handle it here.
            return Error(EWOULDBLOCK) << "SSL_write(): " << SSL_error_description(err);
        }
        return Error() << "SSL_write(): " << SSL_error_description(err);
    }
    LOG_TLS_DETAIL("TLS: Sent %d bytes!", ret);
    return ret;
}

Result<size_t> RpcTransportTls::recv(void *buf, size_t size) {
    size_t todo = std::min<size_t>(size, std::numeric_limits<int>::max());
    int ret = SSL_read(mSsl.get(), buf, todo);
    if (ret < 0) {
        int err = SSL_get_error(mSsl.get(), ret);
        if (err == SSL_ERROR_WANT_READ) {
            // SSL_ERROR_WANT_READ only happens when the socket is non-blocking. This is similar to
            // EAGAIN / EWOULDBLOCK on recv(2). Like RpcTransportRaw::recv(), don't handle it here.
            return Error(EWOULDBLOCK) << "SSL_read(): " << SSL_error_description(err);
        }
        return Error() << "SSL_read(): " << SSL_error_description(err);
    }
    LOG_TLS_DETAIL("TLS: Received %d bytes!", ret);
    return ret;
}

Result<size_t> RpcTransportTls::peek(void *buf, size_t size) {
    // SSL_peek() eventually calls socketRead() above, which doesn't specify MSG_DONTWAIT.
    // Emulate MSG_DONTWAIT by polling with no timeout.
    pollfd pfd{.fd = mSocket.get(), .events = POLLIN, .revents = 0};
    int pollRes = TEMP_FAILURE_RETRY(poll(&pfd, 1, 0 /* no timeout */));
    if (pollRes == -1) {
        return ErrnoError() << "poll()";
    }
    if (pfd.revents & POLLHUP) {
        ALOGE("%s: closed", __PRETTY_FUNCTION__);
        return -1;
    }
    if ((pfd.revents & POLLIN) == 0) {
        // No data pending on the raw socket FD. Check userspace buffer.
        if (!pending()) {
            // No data in userspace buffer either. RpcTransportRaw::peek() would return -1 with
            // EAGAIN or EWOULDBLOCK.
            return Error() << "RpcTransportTls::peek(): no data available for now.";
        }
    }

    int ret = SSL_peek(mSsl.get(), buf, size);
    if (ret < 0) {
        int err = SSL_get_error(mSsl.get(), ret);
        if (err == SSL_ERROR_WANT_READ) {
            // SSL_ERROR_WANT_READ only happens when the socket is non-blocking. This is similar to
            // EAGAIN / EWOULDBLOCK on recv(2). Like RpcTransportRaw::peek(), don't handle it here.
            return Error(EWOULDBLOCK) << "SSL_peek(): " << SSL_error_description(err);
        }
        return Error() << "SSL_peek(): " << SSL_error_description(err);
    }
    LOG_TLS_DETAIL("TLS: Peeked %d bytes!", ret);
    return ret;
}

bool RpcTransportTls::pending() {
    return static_cast<bool>(SSL_pending(mSsl.get()));
}

bssl::UniquePtr<SSL> connectOrAccept(SSL_CTX *ctx, android::base::borrowed_fd fd,
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

    for (int i = 0; i < 5; i++) {
        int ret = fn(ssl.get());
        if (ret > 0) {
            return ssl;
        }
        int err = SSL_get_error(ssl.get(), ret);
        ALOGE("%s(): %s", fnString, SSL_error_description(err));
        if (err != SSL_ERROR_WANT_ACCEPT && err != SSL_ERROR_WANT_CONNECT) {
            return nullptr;
        }
        // Hit EAGAIN / EWOULDBLOCK on non-blocking sockets. Retry a little bit.
    }
    ALOGE("%s(): hit EAGAIN / EWOULDBLOCK for 5 times, rejecting", fnString);
    return nullptr;
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
        android::base::unique_fd acceptedFd) const {
    auto ssl = connectOrAccept(mCtx.get(), acceptedFd, &SSL_accept, "SSL_accept");
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
        android::base::unique_fd connectedFd) const {
    // No certificate verification configured because we only want passively-secure connections.
    // TODO(b/195166979): server should send certificate in a different channel, and client
    //  should verify it here.
    auto ssl = connectOrAccept(mCtx.get(), connectedFd, &SSL_connect, "SSL_connect");
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
