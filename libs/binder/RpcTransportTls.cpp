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

#include <openssl/bn.h>
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

// Implement BIO for socket that ignores SIGPIPE.
int socketNew(BIO *bio) {
    BIO_set_data(bio, reinterpret_cast<void *>(-1));
    BIO_set_init(bio, 0);
    return 1;
}
int socketFree(BIO *bio) {
    LOG_ALWAYS_FATAL_IF(bio == nullptr);
    return 1;
}
int socketRead(BIO *bio, char *buf, int size) {
    android::base::borrowed_fd fd(static_cast<int>(reinterpret_cast<intptr_t>(BIO_get_data(bio))));
    int ret = TEMP_FAILURE_RETRY(::recv(fd.get(), buf, size, MSG_NOSIGNAL));
    BIO_clear_retry_flags(bio);
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        BIO_set_retry_read(bio);
    }
    return ret;
}

int socketWrite(BIO *bio, const char *buf, int size) {
    android::base::borrowed_fd fd(static_cast<int>(reinterpret_cast<intptr_t>(BIO_get_data(bio))));
    int ret = TEMP_FAILURE_RETRY(::send(fd.get(), buf, size, MSG_NOSIGNAL));
    BIO_clear_retry_flags(bio);
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
        BIO_set_retry_write(bio);
    }
    return ret;
}

long socketCtrl(BIO *bio, int cmd, long num, void *) { // NOLINT
    android::base::borrowed_fd fd(static_cast<int>(reinterpret_cast<intptr_t>(BIO_get_data(bio))));
    if (cmd == BIO_CTRL_FLUSH) return 1;
    LOG_ALWAYS_FATAL("sockCtrl(fd=%d, %d, %ld)", fd.get(), cmd, num);
    return 0;
}

std::string toString(X509 *x509) {
    bssl::UniquePtr<BIO> certBio(BIO_new(BIO_s_mem()));
    TEST_AND_RETURN({}, PEM_write_bio_X509(certBio.get(), x509));
    const uint8_t *data;
    size_t len;
    TEST_AND_RETURN({}, BIO_mem_contents(certBio.get(), &data, &len));
    return std::string(reinterpret_cast<const char *>(data), len);
}

bssl::UniquePtr<X509> fromString(std::string_view s) {
    bssl::UniquePtr<BIO> certBio(BIO_new_mem_buf(s.data(), s.length()));
    return bssl::UniquePtr<X509>(PEM_read_bio_X509(certBio.get(), nullptr, nullptr, nullptr));
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
    bssl::UniquePtr<BIGNUM> serialLimit(BN_new());
    TEST_AND_RETURN(nullptr, BN_lshift(serialLimit.get(), BN_value_one(), 128));
    TEST_AND_RETURN(nullptr, BN_rand_range(serial.get(), serialLimit.get()));
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

// Handles libssl's error queue.
//
// Call into any of its member functions to ensure the error queue is properly handled or cleared.
// If the error queue is not handled or cleared, the destructor will abort.
class ErrorQueue {
public:
    ~ErrorQueue() { LOG_ALWAYS_FATAL_IF(!mHandled); }

    // Clear the error queue.
    void clear() {
        ERR_clear_error();
        mHandled = true;
    }

    // Stores the error queue in |ssl| into a string, then clears the error queue.
    std::string toString() {
        std::stringstream ss;
        ERR_print_errors_cb(
                [](const char *str, size_t len, void *ctx) {
                    auto ss = (std::stringstream *)ctx;
                    (*ss) << std::string_view(str, len) << "\n";
                    return 1; // continue
                },
                &ss);
        // Though ERR_print_errors_cb should have cleared it, it is okay to clear again.
        clear();
        return ss.str();
    }

    // |sslError| should be from Ssl::getError().
    // If |sslError| is WANT_READ / WANT_WRITE, poll for POLLIN / POLLOUT respectively. Otherwise
    // return error. Also return error if |fdTrigger| is triggered before or during poll().
    status_t pollForSslError(android::base::borrowed_fd fd, int sslError, FdTrigger *fdTrigger,
                             const char *fnString, int additionalEvent = 0) {
        switch (sslError) {
            case SSL_ERROR_WANT_READ:
                return handlePoll(POLLIN | additionalEvent, fd, fdTrigger, fnString);
            case SSL_ERROR_WANT_WRITE:
                return handlePoll(POLLOUT | additionalEvent, fd, fdTrigger, fnString);
            case SSL_ERROR_SYSCALL: {
                auto queue = toString();
                LOG_TLS_DETAIL("%s(): %s. Treating as DEAD_OBJECT. Error queue: %s", fnString,
                               SSL_error_description(sslError), queue.c_str());
                return DEAD_OBJECT;
            }
            default: {
                auto queue = toString();
                ALOGE("%s(): %s. Error queue: %s", fnString, SSL_error_description(sslError),
                      queue.c_str());
                return UNKNOWN_ERROR;
            }
        }
    }

private:
    bool mHandled = false;

    status_t handlePoll(int event, android::base::borrowed_fd fd, FdTrigger *fdTrigger,
                        const char *fnString) {
        status_t ret = fdTrigger->triggerablePoll(fd, event);
        if (ret != OK && ret != DEAD_OBJECT && ret != -ECANCELED) {
            ALOGE("triggerablePoll error while poll()-ing after %s(): %s", fnString,
                  statusToString(ret).c_str());
        }
        clear();
        return ret;
    }
};

// Helper to call a function, with its return value instantiable.
template <typename Fn, typename... Args>
struct FuncCaller {
    struct Monostate {};
    static constexpr bool sIsVoid = std::is_void_v<std::invoke_result_t<Fn, Args...>>;
    using Result = std::conditional_t<sIsVoid, Monostate, std::invoke_result_t<Fn, Args...>>;
    static inline Result call(Fn fn, Args &&... args) {
        if constexpr (std::is_void_v<std::invoke_result_t<Fn, Args...>>) {
            std::invoke(fn, std::forward<Args>(args)...);
            return {};
        } else {
            return std::invoke(fn, std::forward<Args>(args)...);
        }
    }
};

// Helper to Ssl::call(). Returns the result to the SSL_* function as well as an ErrorQueue object.
template <typename Fn, typename... Args>
struct SslCaller {
    using RawCaller = FuncCaller<Fn, SSL *, Args...>;
    struct ResultAndErrorQueue {
        typename RawCaller::Result result;
        ErrorQueue errorQueue;
    };
    static inline ResultAndErrorQueue call(Fn fn, SSL *ssl, Args &&... args) {
        LOG_ALWAYS_FATAL_IF(ssl == nullptr);
        auto result = RawCaller::call(fn, std::forward<SSL *>(ssl), std::forward<Args>(args)...);
        return ResultAndErrorQueue{std::move(result), ErrorQueue()};
    }
};

// A wrapper over bssl::UniquePtr<SSL>. This class ensures that all SSL_* functions are called
// through call(), which returns an ErrorQueue object that requires the caller to either handle
// or clear it.
// Example:
//   auto [ret, errorQueue] = ssl.call(SSL_read, buf, size);
//   if (ret >= 0) errorQueue.clear();
//   else ALOGE("%s", errorQueue.toString().c_str());
class Ssl {
public:
    explicit Ssl(bssl::UniquePtr<SSL> ssl) : mSsl(std::move(ssl)) {
        LOG_ALWAYS_FATAL_IF(mSsl == nullptr);
    }

    template <typename Fn, typename... Args>
    inline typename SslCaller<Fn, Args...>::ResultAndErrorQueue call(Fn fn, Args &&... args) {
        return SslCaller<Fn, Args...>::call(fn, mSsl.get(), std::forward<Args>(args)...);
    }

    int getError(int ret) {
        LOG_ALWAYS_FATAL_IF(mSsl == nullptr);
        return SSL_get_error(mSsl.get(), ret);
    }

private:
    bssl::UniquePtr<SSL> mSsl;
};

class RpcTransportTls : public RpcTransport {
public:
    RpcTransportTls(android::base::unique_fd socket, Ssl ssl)
          : mSocket(std::move(socket)), mSsl(std::move(ssl)) {}
    Result<size_t> peek(void *buf, size_t size) override;
    status_t interruptableWriteFully(FdTrigger *fdTrigger, const void *data, size_t size) override;
    status_t interruptableReadFully(FdTrigger *fdTrigger, void *data, size_t size) override;

private:
    android::base::unique_fd mSocket;
    Ssl mSsl;

    static status_t isTriggered(FdTrigger *fdTrigger);
};

// Error code is errno.
Result<size_t> RpcTransportTls::peek(void *buf, size_t size) {
    size_t todo = std::min<size_t>(size, std::numeric_limits<int>::max());
    auto [ret, errorQueue] = mSsl.call(SSL_peek, buf, static_cast<int>(todo));
    if (ret < 0) {
        int err = mSsl.getError(ret);
        if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) {
            // Seen EAGAIN / EWOULDBLOCK on recv(2) / send(2).
            // Like RpcTransportRaw::peek(), don't handle it here.
            return Error(EWOULDBLOCK) << "SSL_peek(): " << errorQueue.toString();
        }
        return Error() << "SSL_peek(): " << errorQueue.toString();
    }
    errorQueue.clear();
    LOG_TLS_DETAIL("TLS: Peeked %d bytes!", ret);
    return ret;
}

status_t RpcTransportTls::isTriggered(FdTrigger *fdTrigger) {
    auto isTriggered = fdTrigger->isTriggeredPolled();
    if (!isTriggered.ok()) {
        ALOGE("%s: %s", __PRETTY_FUNCTION__, isTriggered.error().message().c_str());
        return isTriggered.error().code() == 0 ? UNKNOWN_ERROR : -isTriggered.error().code();
    }
    return OK;
}

status_t RpcTransportTls::interruptableWriteFully(FdTrigger *fdTrigger, const void *data,
                                                  size_t size) {
    auto buffer = reinterpret_cast<const uint8_t *>(data);
    const uint8_t *end = buffer + size;

    MAYBE_WAIT_IN_FLAKE_MODE;

    // Before doing any I/O, check trigger once. This ensures the trigger is checked at least
    // once. The trigger is also checked via triggerablePoll() after every SSL_write().
    if (status_t status = isTriggered(fdTrigger); status != OK) return status;

    while (buffer < end) {
        size_t todo = std::min<size_t>(end - buffer, std::numeric_limits<int>::max());
        auto [writeSize, errorQueue] = mSsl.call(SSL_write, buffer, todo);
        if (writeSize > 0) {
            buffer += writeSize;
            errorQueue.clear();
            continue;
        }
        // SSL_write() should never return 0 unless BIO_write were to return 0.
        int sslError = mSsl.getError(writeSize);
        // TODO(b/195788248): BIO should contain the FdTrigger, and send(2) / recv(2) should be
        //   triggerablePoll()-ed. Then additionalEvent is no longer necessary.
        status_t pollStatus =
                errorQueue.pollForSslError(mSocket.get(), sslError, fdTrigger, "SSL_write", POLLIN);
        if (pollStatus != OK) return pollStatus;
        // Do not advance buffer. Try SSL_write() again.
    }
    LOG_TLS_DETAIL("TLS: Sent %zu bytes!", size);
    return OK;
}

status_t RpcTransportTls::interruptableReadFully(FdTrigger *fdTrigger, void *data, size_t size) {
    auto buffer = reinterpret_cast<uint8_t *>(data);
    uint8_t *end = buffer + size;

    MAYBE_WAIT_IN_FLAKE_MODE;

    // Before doing any I/O, check trigger once. This ensures the trigger is checked at least
    // once. The trigger is also checked via triggerablePoll() after every SSL_write().
    if (status_t status = isTriggered(fdTrigger); status != OK) return status;

    while (buffer < end) {
        size_t todo = std::min<size_t>(end - buffer, std::numeric_limits<int>::max());
        auto [readSize, errorQueue] = mSsl.call(SSL_read, buffer, todo);
        if (readSize > 0) {
            buffer += readSize;
            errorQueue.clear();
            continue;
        }
        if (readSize == 0) {
            // SSL_read() only returns 0 on EOF.
            errorQueue.clear();
            return DEAD_OBJECT;
        }
        int sslError = mSsl.getError(readSize);
        status_t pollStatus =
                errorQueue.pollForSslError(mSocket.get(), sslError, fdTrigger, "SSL_read");
        if (pollStatus != OK) return pollStatus;
        // Do not advance buffer. Try SSL_read() again.
    }
    LOG_TLS_DETAIL("TLS: Received %zu bytes!", size);
    return OK;
}

// For |ssl|, set internal FD to |fd|, and do handshake. Handshake is triggerable by |fdTrigger|.
bool setFdAndDoHandshake(Ssl *ssl, android::base::borrowed_fd fd, FdTrigger *fdTrigger) {
    bssl::UniquePtr<BIO> bio = newSocketBio(fd);
    TEST_AND_RETURN(false, bio != nullptr);
    {
        auto [_, errorQueue] = ssl->call(SSL_set_bio, bio.get(), bio.get());
        (void)bio.release(); // SSL_set_bio takes ownership.
        errorQueue.clear();
    }

    MAYBE_WAIT_IN_FLAKE_MODE;

    while (true) {
        auto [ret, errorQueue] = ssl->call(SSL_do_handshake);
        if (ret > 0) {
            errorQueue.clear();
            return true;
        }
        if (ret == 0) {
            // SSL_do_handshake() only returns 0 on EOF.
            ALOGE("SSL_do_handshake(): EOF: %s", errorQueue.toString().c_str());
            return false;
        }
        int sslError = ssl->getError(ret);
        status_t pollStatus =
                errorQueue.pollForSslError(fd, sslError, fdTrigger, "SSL_do_handshake");
        if (pollStatus != OK) return false;
    }
}

class RpcTransportCtxTlsServer : public RpcTransportServerCtx {
public:
    static std::unique_ptr<RpcTransportCtxTlsServer> create();
    std::unique_ptr<RpcTransport> newTransport(android::base::unique_fd acceptedFd,
                                               FdTrigger *fdTrigger) const override;
    std::string getCertificate() override;

private:
    bssl::UniquePtr<SSL_CTX> mCtx;
};

std::unique_ptr<RpcTransportCtxTlsServer> RpcTransportCtxTlsServer::create() {
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
    TEST_AND_RETURN(nullptr, ctx != nullptr);

    // Server use self-signing cert
    auto evp_pkey = makeKeyPairForSelfSignedCert();
    TEST_AND_RETURN(nullptr, evp_pkey != nullptr);
    auto cert = makeSelfSignedCert(evp_pkey.get(), kCertValidDays);
    TEST_AND_RETURN(nullptr, cert != nullptr);
    TEST_AND_RETURN(nullptr, SSL_CTX_use_PrivateKey(ctx.get(), evp_pkey.get()));
    TEST_AND_RETURN(nullptr, SSL_CTX_use_certificate(ctx.get(), cert.get()));

    LOG_TLS_DETAIL("Server: using certificate: %s", toString(cert.get()).c_str());

    // TODO: Also SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT on server!
    //    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER);

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
    Ssl wrapped(std::move(ssl));

    wrapped.call(SSL_set_accept_state).errorQueue.clear();
    TEST_AND_RETURN(nullptr, setFdAndDoHandshake(&wrapped, acceptedFd, fdTrigger));
    return std::make_unique<RpcTransportTls>(std::move(acceptedFd), std::move(wrapped));
}

std::string RpcTransportCtxTlsServer::getCertificate() {
    X509 *x509 = SSL_CTX_get0_certificate(mCtx.get()); // does not own
    auto ret = toString(x509);
    LOG_ALWAYS_FATAL_IF(ret.empty(), "No pre-configured certificate!");
    return ret;
}

class RpcTransportCtxTlsClient : public RpcTransportClientCtx {
public:
    static std::unique_ptr<RpcTransportCtxTlsClient> create();
    std::unique_ptr<RpcTransport> newTransport(android::base::unique_fd connectedFd,
                                               FdTrigger *fdTrigger) const override;
    status_t addTrustedCertificate(std::string_view cert) override;

private:
    bssl::UniquePtr<SSL_CTX> mCtx;
};

std::unique_ptr<RpcTransportCtxTlsClient> RpcTransportCtxTlsClient::create() {
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));
    TEST_AND_RETURN(nullptr, ctx != nullptr);

    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);

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
    bssl::UniquePtr<SSL> ssl(SSL_new(mCtx.get()));
    TEST_AND_RETURN(nullptr, ssl != nullptr);
    Ssl wrapped(std::move(ssl));

    wrapped.call(SSL_set_connect_state).errorQueue.clear();
    TEST_AND_RETURN(nullptr, setFdAndDoHandshake(&wrapped, connectedFd, fdTrigger));

    if constexpr (SHOULD_LOG_TLS_DETAIL) {
        auto [x509p, peerCertErrorQueue] = wrapped.call(SSL_get_peer_certificate);
        if (x509p == nullptr) {
            ALOGE("Client: SSL_get_peer_certificate(): no peer certificate: %s",
                  peerCertErrorQueue.toString().c_str());
        } else {
            peerCertErrorQueue.clear();
            bssl::UniquePtr<X509> x509(x509p);
            LOG_TLS_DETAIL("Client: got peer certificate: %s", toString(x509.get()).c_str());
        }
    }

    return std::make_unique<RpcTransportTls>(std::move(connectedFd), std::move(wrapped));
}

status_t RpcTransportCtxTlsClient::addTrustedCertificate(std::string_view cert) {
    X509_STORE *store = SSL_CTX_get_cert_store(mCtx.get());
    LOG_ALWAYS_FATAL_IF(store == nullptr);
    TEST_AND_RETURN(BAD_VALUE, X509_STORE_add_cert(store, fromString(cert).get()));
    return OK;
}

} // namespace

std::unique_ptr<RpcTransportServerCtx> RpcTransportCtxFactoryTls::newServerCtx() const {
    return android::RpcTransportCtxTlsServer::create();
}

std::unique_ptr<RpcTransportClientCtx> RpcTransportCtxFactoryTls::newClientCtx() const {
    return android::RpcTransportCtxTlsClient::create();
}

const char *RpcTransportCtxFactoryTls::toCString() const {
    return "tls";
}

std::unique_ptr<RpcTransportCtxFactory> RpcTransportCtxFactoryTls::make() {
    return std::unique_ptr<RpcTransportCtxFactoryTls>(new RpcTransportCtxFactoryTls());
}

} // namespace android
