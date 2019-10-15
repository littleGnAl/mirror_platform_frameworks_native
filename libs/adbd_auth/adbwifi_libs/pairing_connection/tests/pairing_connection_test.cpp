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

#define LOG_TAG "AdbWifiPairingConnectionTest"

#include <gtest/gtest.h>

#include <adbwifi/pairing/pairing_connection.h>

namespace adbwifi {
namespace pairing {

class AdbWifiPairingConnectionTest : public testing::Test {
protected:
    virtual void SetUp() override {
    }

    virtual void TearDown() override {
    }

    void initPairing(const std::vector<uint8_t> server_pswd,
                     const std::vector<uint8_t> client_pswd) {
        server_ = PairingConnection::create(PairingConnection::Role::Server,
                                              server_pswd,
                                              server_cert_);
        client_ = PairingConnection::create(PairingConnection::Role::Client,
                                              client_pswd,
                                              client_cert_,
                                              "127.0.0.1");
    }

    std::unique_ptr<PairingConnection> server_;
    const std::vector<uint8_t> server_cert_{0x01, 0x02, 0x03, 0x04};
    std::unique_ptr<PairingConnection> client_;
    const std::vector<uint8_t> client_cert_{0x05, 0x06, 0x07, 0x08};
};

TEST_F(AdbWifiPairingConnectionTest, Creation) {
    auto roles = { PairingConnection::Role::Server,
                   PairingConnection::Role::Client };
    std::string ip_addr = "1.2.3.4";
    for (auto role : roles) {
        // Empty password and certificate shouldn't work
        auto connection = PairingConnection::create(role, {}, {}, ip_addr);
        EXPECT_EQ(nullptr, connection);
        // Or just empty password
        connection = PairingConnection::create(role, {}, {0x01}, ip_addr);
        EXPECT_EQ(nullptr, connection);
        // Or just empty certificate
        connection = PairingConnection::create(role, {0x01}, {}, ip_addr);
        EXPECT_EQ(nullptr, connection);
        // A valid connection
        connection = PairingConnection::create(role, {0x01}, {0x01}, ip_addr);
        EXPECT_NE(nullptr, connection);
    }
}

TEST_F(AdbWifiPairingConnectionTest, ClientIpAddr) {
    std::vector<uint8_t> client_pswd{0x01, 0x02};

    // Cannot give empty ip_addr for Role::Client
    client_ = PairingConnection::create(PairingConnection::Role::Client,
                                          client_pswd,
                                          client_cert_,
                                          "");
    EXPECT_EQ(nullptr, client_);

    // User-defined ports are not allowed.
    client_ = PairingConnection::create(PairingConnection::Role::Client,
                                          client_pswd,
                                          client_cert_,
                                          "127.0.0.1:12345");
    EXPECT_EQ(nullptr, client_);

    // Valid ipv4 address
    client_ = PairingConnection::create(PairingConnection::Role::Client,
                                          client_pswd,
                                          client_cert_,
                                          "127.0.0.1");
    EXPECT_NE(nullptr, client_);

    // Valid ipv6 address
    client_ = PairingConnection::create(PairingConnection::Role::Client,
                                          client_pswd,
                                          client_cert_,
                                          "::1");
    EXPECT_NE(nullptr, client_);
}

TEST_F(AdbWifiPairingConnectionTest, ValidPairing) {
    PairingConnection::Data pswd{0xaa, 0xbb, 0xcc, 0xdd};
    PairingConnection::Data client_peer_cert;
    PairingConnection::Data server_peer_cert;

    initPairing(pswd, pswd);
    server_->start([&](const PairingConnection::Data& cert, void* /* opaque */) {
        server_peer_cert = cert;
    }, nullptr);
    client_->start([&](const PairingConnection::Data& cert, void* /* opaque */) {
        client_peer_cert = cert;
    }, nullptr);
    server_->wait();
    client_->wait();

    // TODO: fake certificate. Check against the real one
    uint8_t c = 0x01;
    EXPECT_EQ(1, client_peer_cert.size());
    EXPECT_TRUE(memcmp(client_peer_cert.data(), &c, client_peer_cert.size()) == 0);
    EXPECT_EQ(1, server_peer_cert.size());
    EXPECT_TRUE(memcmp(server_peer_cert.data(), &c, server_peer_cert.size()) == 0);
}

}  // namespace pairing
}  // namespace adbwifi
