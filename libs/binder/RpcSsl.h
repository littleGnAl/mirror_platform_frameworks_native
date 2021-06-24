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
#pragma once

#include <poll.h>

#include <memory>

#include <android-base/unique_fd.h>

#if BINDER_ENABLE_SSL
#include <openssl/ssl.h>
#endif

#define BINDER_SSL_LOG_DEBUG false

namespace android {

class RpcSslCtx;
class RpcSsl;

// Wrapper of SSL for libbinder usage.
class RpcSsl {
public:
    // replacement of ::send(). errno may not be set if SSL is enabled.
    int send(const void *buf, int size);
    // replacement of ::recv(). errno may not be set if SSL is enabled.
    int recv(void *buf, int size);

private:
    friend RpcSslCtx;
#if BINDER_ENABLE_SSL
    bssl::UniquePtr<SSL> mSsl;
#endif
    android::base::unique_fd mSocket;
};

// Wrapper of SSL_CTX for libbinder usage.
class RpcSslCtx {
public:
    static std::unique_ptr<RpcSslCtx> create(android::base::unique_fd sockfd);
    android::base::borrowed_fd rawServerFd() const { return mServer; }
    std::unique_ptr<RpcSsl> sslAccept(android::base::unique_fd acceptedFd, bool* retry);

private:
#if BINDER_ENABLE_SSL
    static bssl::UniquePtr<EVP_PKEY> MakeKeyPairForSelfSignedCert();
    static bssl::UniquePtr<X509> MakeSelfSignedCert(EVP_PKEY *evp_pkey, const int valid_days);
#endif
    static void SslDebugLog(const SSL *ssl, int type, int value);

#if BINDER_ENABLE_SSL
    bssl::UniquePtr<SSL_CTX> mCtx;
#endif
    android::base::unique_fd mServer;
};

} // namespace android
