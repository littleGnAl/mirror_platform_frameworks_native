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

#define LOG_TAG "RpcCertificateUtils"
#include <log/log.h>

#include <binder/RpcCertificateUtils.h>

#include "Utils.h"

namespace android {

namespace {

bssl::UniquePtr<X509> fromPem(std::string_view s) {
    if (s.length() > std::numeric_limits<int>::max()) return nullptr;
    bssl::UniquePtr<BIO> certBio(BIO_new_mem_buf(s.data(), static_cast<int>(s.length())));
    return bssl::UniquePtr<X509>(PEM_read_bio_X509(certBio.get(), nullptr, nullptr, nullptr));
}

} // namespace

bssl::UniquePtr<X509> certificateFromString(std::string_view s, CertificateFormat format) {
    switch (format) {
        case CertificateFormat::PEM:
            return fromPem(s);
    }
    LOG_ALWAYS_FATAL("Unsupported format %d", static_cast<int>(format));
}

std::string toString(X509* x509, CertificateFormat format) {
    bssl::UniquePtr<BIO> certBio(BIO_new(BIO_s_mem()));
    switch (format) {
        case CertificateFormat::PEM: {
            TEST_AND_RETURN({}, PEM_write_bio_X509(certBio.get(), x509));
        } break;
        default: {
            LOG_ALWAYS_FATAL("Unsupported format %d", static_cast<int>(format));
        }
    }
    const uint8_t* data;
    size_t len;
    TEST_AND_RETURN({}, BIO_mem_contents(certBio.get(), &data, &len));
    return std::string(reinterpret_cast<const char*>(data), len);
}

} // namespace android
