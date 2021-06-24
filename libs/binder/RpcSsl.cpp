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

#include "RpcSsl.h"

#include <log/log.h>

namespace android {

int RpcSsl::send(const void *buf, int size) {
    while (true) {
        pollfd pfd{.fd = mSocket.get(), .events = POLLOUT, .revents = 0};
        int pollRes = TEMP_FAILURE_RETRY(poll(&pfd, 1, -1 /* infinite timeout */));
        if (pollRes == -1) {
            ALOGE("%s: poll(): %s", __PRETTY_FUNCTION__, strerror(errno));
            return -1;
        }
        if (pfd.revents & POLLHUP) {
            ALOGE("%s: closed", __PRETTY_FUNCTION__);
            return -1;
        }
        if ((pfd.revents & POLLOUT) == 0) continue;

#if BINDER_ENABLE_SSL
        int ret = SSL_write(mSsl.get(), buf, size);
        if (ret <= 0) {
            int err = SSL_get_error(mSsl.get(), ret);
            if (err == SSL_ERROR_WANT_WRITE) {
                continue;
            }
            ALOGE("%s: SSL_write() error: %s", __PRETTY_FUNCTION__, SSL_error_description(err));
            return -1;
        }
#else
        int ret = TEMP_FAILURE_RETRY(::send(mSocket.get(), buf, size, MSG_NOSIGNAL));
        if (ret <= 0) {
            ALOGE("%s: send(): %s", __PRETTY_FUNCTION__, strerror(errno));
            return ret;
        }
#endif
        return ret;
    }
}

int RpcSsl::recv(void *buf, int size) {
    while (true) {
        pollfd pfd{.fd = mSocket.get(), .events = POLLIN, .revents = 0};
        int pollRes = TEMP_FAILURE_RETRY(poll(&pfd, 1, -1 /* infinite timeout */));
        if (pollRes == -1) {
            ALOGE("%s: poll(): %s", __PRETTY_FUNCTION__, strerror(errno));
            return -1;
        }
        if (pfd.revents & POLLHUP) {
            ALOGE("%s: closed", __PRETTY_FUNCTION__);
            return -1;
        }
        if ((pfd.revents & POLLIN) == 0) continue;

#if BINDER_ENABLE_SSL
        int ret = SSL_read(mSsl.get(), buf, size);
        if (ret < 0) {
            int err = SSL_get_error(mSsl.get(), ret);
            if (err == SSL_ERROR_WANT_READ) {
                continue;
            }
            ALOGE("%s: SSL_read() error: %s", __PRETTY_FUNCTION__, SSL_error_description(err));
            return -1;
        }
#else
        int ret = TEMP_FAILURE_RETRY(::recv(mSocket.get(), buf, size));
        if (ret < 0) {
            ALOGE("%s: recv(): %s", __PRETTY_FUNCTION__, strerror(errno));
            return ret;
        }
#endif
        return ret;
    }
}

// Wrapper of SSL_CTX for libbinder usage.

std::unique_ptr<RpcSslCtx> RpcSslCtx::create(android::base::unique_fd sockfd) {
#if BINDER_ENABLE_SSL
    bssl::UniquePtr<SSL_CTX> ctx(SSL_CTX_new(TLS_method()));

    // Server use self-signing cert
    auto evp_pkey = MakeKeyPairForSelfSignedCert();
    if (evp_pkey == nullptr) {
        return nullptr;
    }
    auto cert = MakeSelfSignedCert(evp_pkey.get(), 365 /* valid_days */);
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
    if (BINDER_SSL_LOG_DEBUG) {
        SSL_CTX_set_info_callback(ctx.get(), SslDebugLog);
    }

    // Require at least TLS 1.3
    if (!SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION)) {
        ALOGE("SSL_CTX_set_min_proto_version(1.3)");
        return nullptr;
    }
#endif

    auto rpcSslCtx = std::make_unique<RpcSslCtx>();
    rpcSslCtx->mServer = std::move(sockfd);
#if BINDER_ENABLE_SSL
    rpcSslCtx->mCtx = std::move(ctx);
#endif

    return rpcSslCtx;
}

std::unique_ptr<RpcSsl> RpcSslCtx::sslAccept(android::base::unique_fd acceptedFd, bool *retry) {
    *retry = false;
#if BINDER_ENABLE_SSL
    bssl::UniquePtr<SSL> ssl(SSL_new(mCtx.get()));
    if (int ret = SSL_set_fd(ssl.get(), acceptedFd); ret != 1) {
        ALOGE("SSL_set_fd()");
        return nullptr;
    }
    if (int ret = SSL_accept(ssl.get()); ret != 1) {
        *retry = true;
        ALOGE("SSL_accept()");
        return nullptr;
    }
#endif

    auto rpcSsl = std::make_unique<RpcSsl>();
    rpcSsl->mSocket = std::move(acceptedFd);
#if BINDER_ENABLE_SSL
    rpcSsl->mSsl = std::move(ssl);
#endif
    return rpcSsl;
}

#if BINDER_ENABLE_SSL

bssl::UniquePtr<EVP_PKEY> MakeKeyPairForSelfSignedCert() {
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

bssl::UniquePtr<X509> MakeSelfSignedCert(EVP_PKEY *evp_pkey, const int valid_days) {
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
                               reinterpret_cast<const uint8_t *>("BoringSSL"), -1, -1, 0);
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
#endif

static void RpcSslCtx::SslDebugLog(const SSL *ssl, int type, int value) {
    switch (type) {
        case SSL_CB_HANDSHAKE_START:
            ALOGI("Handshake started.");
            break;
        case SSL_CB_HANDSHAKE_DONE:
            ALOGI("Handshake done.");
            break;
        case SSL_CB_ACCEPT_LOOP:
            ALOGI("Handshake progress: %s", SSL_state_string_long(ssl));
            break;
    }
}

} // namespace android
