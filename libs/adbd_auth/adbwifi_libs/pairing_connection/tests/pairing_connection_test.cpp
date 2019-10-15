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

#include <adbwifi/pairing/pairing_server.h>
#include <adbwifi/pairing/pairing_client.h>

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
        server_ = PairingServer::create(server_pswd,
                                        server_cert_,
                                        server_priv_key_,
                                        kDefaultPairingPort);
        client_ = PairingClient::create(client_pswd,
                                        client_cert_,
                                        client_priv_key_,
                                        "127.0.0.1");
    }

    std::unique_ptr<PairingServer> server_;
    const std::vector<uint8_t> server_cert_{0x01, 0x02, 0x03, 0x04};
    const std::vector<uint8_t> server_priv_key_{0x11, 0x12, 0x13, 0x14};
    std::unique_ptr<PairingClient> client_;
    const std::vector<uint8_t> client_cert_{0x05, 0x06, 0x07, 0x08};
    const std::vector<uint8_t> client_priv_key_{0x25, 0x26, 0x27, 0x28};
};

TEST_F(AdbWifiPairingConnectionTest, ServerCreation) {
    // All parameters bad
    auto server = PairingServer::create({}, {}, {}, -1);
    EXPECT_EQ(nullptr, server);
    // Bad password
    server = PairingServer::create({}, {0x01}, {0x01}, -1);
    EXPECT_EQ(nullptr, server);
    // Bad certificate
    server = PairingServer::create({0x01}, {}, {0x01}, -1);
    EXPECT_EQ(nullptr, server);
    // Bad private key
    server = PairingServer::create({0x01}, {0x01}, {}, -1);
    EXPECT_EQ(nullptr, server);
    // Bad port
    server = PairingServer::create({0x01}, {0x01}, {0x01}, -1);
    EXPECT_EQ(nullptr, server);
    // Valid params
    server = PairingServer::create({0x01}, {0x01}, {0x01}, 5555);
    EXPECT_EQ(nullptr, server);
}

TEST_F(AdbWifiPairingConnectionTest, ClientCreation) {
    // All parameters bad
    auto client = PairingClient::create({}, {}, {}, "");
    EXPECT_EQ(nullptr, client);
    // Bad password
    client = PairingClient::create({}, {0x01}, {0x01}, "127.0.0.1");
    EXPECT_EQ(nullptr, client);
    // Bad certificate
    client = PairingClient::create({0x01}, {}, {0x01}, "127.0.0.1");
    EXPECT_EQ(nullptr, client);
    // Bad private key
    client = PairingClient::create({0x01}, {0x01}, {}, "127.0.0.1");
    EXPECT_EQ(nullptr, client);
    // Bad ip address
    client = PairingClient::create({0x01}, {0x01}, {0x01}, "");
    EXPECT_EQ(nullptr, client);
    // Valid params
    client = PairingClient::create({0x01}, {0x01}, {0x01}, "127.0.0.1");
    EXPECT_EQ(nullptr, client);
}

TEST_F(AdbWifiPairingConnectionTest, ValidPairing) {
}

}  // namespace pairing
}  // namespace adbwifi
