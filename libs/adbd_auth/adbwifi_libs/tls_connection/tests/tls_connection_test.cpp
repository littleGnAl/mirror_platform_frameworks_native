/*
 * Copyright 2013 The Android Open Source Project
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

#define LOG_TAG "AdbWifiTlsConnectionTest"

#include <thread>

#include <gtest/gtest.h>

#include <adbwifi/ssl/tls_connection.h>
#include <adbwifi/sysdeps/sysdeps.h>

namespace adbwifi {
namespace ssl {

static const std::string kTestServerCert =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBljCCAT2gAwIBAgIBATAKBggqhkjOPQQDAjAzMQswCQYDVQQGEwJVUzEQMA4G\n"
        "A1UECgwHQW5kcm9pZDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTE5MTEwNzAyMDkx\n"
        "NVoXDTI5MTEwNDAyMDkxNVowMzELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0FuZHJv\n"
        "aWQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA\n"
        "BCXRovy3RhtK0Khle48vUmkcuI0OF7K8o9sVPE4oVnp24l+cCYr3BtrgifoHPgj4\n"
        "vq7n105qzK7ngBHH+LBmYIijQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/\n"
        "BAQDAgGGMB0GA1UdDgQWBBQi4eskzqVG3SCX2CwJF/aTZqUcuTAKBggqhkjOPQQD\n"
        "AgNHADBEAiBPYvLOCIvPDtq3vMF7A2z7t7JfcCmbC7g8ftEVJucJBwIgepf+XjTb\n"
        "L7RCE16p7iVkpHUrWAOl7zDxqD+jaji5MkQ=\n"
        "-----END CERTIFICATE-----\n";

static const std::string kTestServerPrivKey =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgSCaskWPtutIgh8uQ\n"
        "UBH6ZIea5Kxm7m6kkGNkd8FYPSOhRANCAAQl0aL8t0YbStCoZXuPL1JpHLiNDhey\n"
        "vKPbFTxOKFZ6duJfnAmK9wba4In6Bz4I+L6u59dOasyu54ARx/iwZmCI\n"
        "-----END PRIVATE KEY-----\n";

static const std::string kTestClientCert =
        "-----BEGIN CERTIFICATE-----\n"
        "MIIBlzCCAT2gAwIBAgIBATAKBggqhkjOPQQDAjAzMQswCQYDVQQGEwJVUzEQMA4G\n"
        "A1UECgwHQW5kcm9pZDESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTE5MTEwOTAxNTAy\n"
        "OFoXDTI5MTEwNjAxNTAyOFowMzELMAkGA1UEBhMCVVMxEDAOBgNVBAoMB0FuZHJv\n"
        "aWQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IA\n"
        "BGW+RuoEIzbt42zAuZzbXaC0bvh8n4OLFDnqkkW6kWA43GYg/mUMVc9vg/nuxyuM\n"
        "aT0KqbTaLhm+NjCXVRnxBrajQjBAMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/\n"
        "BAQDAgGGMB0GA1UdDgQWBBTjCaC8/NXgdBz9WlMVCNwhx7jn0jAKBggqhkjOPQQD\n"
        "AgNIADBFAiB/xp2boj7b1KK2saS6BL59deo/TvfgZ+u8HPq4k4VP3gIhAMXswp9W\n"
        "XdlziccQdj+0KpbUojDKeHOr4fIj/+LxsWPa\n"
        "-----END CERTIFICATE-----\n";

static const std::string kTestClientPrivKey =
        "-----BEGIN PRIVATE KEY-----\n"
        "MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgFw/CWY1f6TSB70AF\n"
        "yVe8n6QdYFu8HW5t/tij2SrXx42hRANCAARlvkbqBCM27eNswLmc212gtG74fJ+D\n"
        "ixQ56pJFupFgONxmIP5lDFXPb4P57scrjGk9Cqm02i4ZvjYwl1UZ8Qa2\n"
        "-----END PRIVATE KEY-----\n";

class AdbWifiTlsConnectionTest : public testing::Test {
protected:
    virtual void SetUp() override {
        ASSERT_EQ(0, sysdeps::adb_socketpair(fds_));
        server_ = TlsConnection::create(TlsConnection::Role::Server,
                                        kTestServerCert,
                                        kTestServerPrivKey);
        client_ = TlsConnection::create(TlsConnection::Role::Client,
                                        kTestClientCert,
                                        kTestClientPrivKey);
        ASSERT_NE(nullptr, server_);
        ASSERT_NE(nullptr, client_);
    }

    virtual void TearDown() override {
        waitForClientConnection();
        // Shutdown the SSL connection first.
        server_.reset();
        client_.reset();
        ASSERT_EQ(0, sysdeps::adb_close(fds_[0]));
        ASSERT_EQ(0, sysdeps::adb_close(fds_[1]));
    }

    void setupClientConnectionAsync(bool use_cert_verify) {
          client_thread_ = std::thread([&]() {
              client_->enableCertificateVerification(use_cert_verify);
              if (!client_->doHandshake(fds_[kClientIdx])) {
                  return;
              }
          });
    }

    void waitForClientConnection() {
        if (client_thread_.joinable()) {
            client_thread_.join();
        }
    }

    int fds_[2];
    const int kServerIdx = 0;
    const int kClientIdx = 1;
    const std::string msg_ = "hello world";
    std::unique_ptr<TlsConnection> server_;
    std::unique_ptr<TlsConnection> client_;
    std::thread client_thread_;
};

TEST_F(AdbWifiTlsConnectionTest, NoCertificateVerification) {
    server_->enableCertificateVerification(false);
    setupClientConnectionAsync(false);

    // Handshake should succeed
    EXPECT_TRUE(server_->doHandshake(fds_[kServerIdx]));
    waitForClientConnection();

    // Client write, server read
    EXPECT_TRUE(client_->writeFully(msg_));
    auto data = server_->readFully(msg_.size());
    EXPECT_EQ(data.size(), msg_.size());
    EXPECT_EQ(0, ::memcmp(data.data(), msg_.data(), msg_.size()));

    // Client read, server write
    EXPECT_TRUE(server_->writeFully(msg_));
    data = client_->readFully(msg_.size());
    EXPECT_EQ(data.size(), msg_.size());
    EXPECT_EQ(0, ::memcmp(data.data(), msg_.data(), msg_.size()));
}

TEST_F(AdbWifiTlsConnectionTest, NoTrustedCertificates) {
    server_->enableCertificateVerification(true);
    setupClientConnectionAsync(true);

    // Handshake should not succeed
    EXPECT_FALSE(server_->doHandshake(fds_[kServerIdx]));
    waitForClientConnection();

    // Client write, server read should fail
    EXPECT_FALSE(client_->writeFully(msg_));
    auto data = server_->readFully(msg_.size());
    EXPECT_EQ(data.size(), 0);

    // Client read, server write should fail
    EXPECT_FALSE(server_->writeFully(msg_));
    data = client_->readFully(msg_.size());
    EXPECT_EQ(data.size(), 0);
}

TEST_F(AdbWifiTlsConnectionTest, AddTrustedCertificates) {
    server_->enableCertificateVerification(true);

    // Add peer certificates
    EXPECT_TRUE(client_->addTrustedCertificate(kTestServerCert));
    EXPECT_TRUE(server_->addTrustedCertificate(kTestClientCert));

    setupClientConnectionAsync(true);

    // Handshake should succeed
    EXPECT_TRUE(server_->doHandshake(fds_[kServerIdx]));
    waitForClientConnection();

    // Client write, server read
    EXPECT_TRUE(client_->writeFully(msg_));
    auto data = server_->readFully(msg_.size());
    EXPECT_EQ(data.size(), msg_.size());
    EXPECT_EQ(0, ::memcmp(data.data(), msg_.data(), msg_.size()));

    // Client read, server write
    EXPECT_TRUE(server_->writeFully(msg_));
    data = client_->readFully(msg_.size());
    EXPECT_EQ(data.size(), msg_.size());
    EXPECT_EQ(0, ::memcmp(data.data(), msg_.data(), msg_.size()));
}

}  // namespace ssl
}  // namespace adbwifi
