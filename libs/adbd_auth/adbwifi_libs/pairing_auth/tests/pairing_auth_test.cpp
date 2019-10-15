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

#define LOG_TAG "AdbWifiPairingAuthTest"

#include <gtest/gtest.h>

#include <adbwifi/pairing/pairing_auth.h>

namespace adbwifi {
namespace pairing {

class AdbWifiPairingAuthTest : public testing::Test {
protected:
    virtual void SetUp() override {
    }

    virtual void TearDown() override {
    }

    // Constructs both client and server with the same password.
    void setPassword(std::vector<uint8_t> pswd) {
        client_ = PairingAuth::create(PairingAuth::Role::Client, pswd);
        server_ = PairingAuth::create(PairingAuth::Role::Server, pswd);
    }

    std::unique_ptr<PairingAuth> client_;
    std::unique_ptr<PairingAuth> server_;
};

TEST_F(AdbWifiPairingAuthTest, EmptyPassword) {
    // Context creation should fail if password is empty
    setPassword({});
    EXPECT_EQ(nullptr, client_);
    EXPECT_EQ(nullptr, server_);
}

TEST_F(AdbWifiPairingAuthTest, ValidPassword) {
    const char* kPswd = "password";
    std::vector<uint8_t> pswd(sizeof(kPswd));
    pswd.assign(kPswd, kPswd + sizeof(kPswd));
    setPassword(pswd);

    EXPECT_NE(nullptr, client_);
    EXPECT_NE(nullptr, server_);
    // msg should not be empty.
    EXPECT_FALSE(client_->msg().empty());
    EXPECT_FALSE(server_->msg().empty());
}

TEST_F(AdbWifiPairingAuthTest, NoInitCipherCalled) {
    // Register a non-empty password, but not the peer's msg.
    // You should not be able to encrypt/decrypt messages.
    const char* kPswd = "password";
    std::vector<uint8_t> pswd(sizeof(kPswd));
    pswd.assign(kPswd, kPswd + sizeof(kPswd));
    setPassword(pswd);

    // We shouldn't be able to encrypt/decrypt anything until we register the
    // peer's msg.
    auto data = client_->encrypt({0x01, 0x02, 0x03});
    EXPECT_TRUE(data.empty());
    data = client_->decrypt({0x01, 0x02, 0x03});
    EXPECT_TRUE(data.empty());
    data = server_->encrypt({0x01, 0x02, 0x03});
    EXPECT_TRUE(data.empty());
    data = server_->decrypt({0x01, 0x02, 0x03});
    EXPECT_TRUE(data.empty());

    // Even if we try to register an empty msg
    EXPECT_FALSE(client_->initCipher({}));
    data = client_->encrypt({0x05, 0xaf, 0xec});
    EXPECT_TRUE(data.empty());
    data = client_->decrypt({0x2b, 0xb4, 0x97});
    EXPECT_TRUE(data.empty());
    EXPECT_FALSE(server_->initCipher({}));
    data = server_->encrypt({0x05, 0xaf, 0xec});
    EXPECT_TRUE(data.empty());
    data = server_->decrypt({0x2b, 0xb4, 0x97});
    EXPECT_TRUE(data.empty());
}

TEST_F(AdbWifiPairingAuthTest, DifferentPasswords) {
    // Register different passwords and then exchange the msgs. The
    // encryption should succeed, but the decryption should fail, since the
    // ciphers have been initialized with different keys.
    client_ = PairingAuth::create(PairingAuth::Role::Client,
                                    {0x01, 0x02, 0x03});
    server_ = PairingAuth::create(PairingAuth::Role::Server,
                                    {0x01, 0x02, 0x04});

    EXPECT_TRUE(client_->initCipher(server_->msg()));
    EXPECT_TRUE(server_->initCipher(client_->msg()));

    // We shouldn't be able to decrypt.
    std::vector<uint8_t> msg{0x2a, 0x2b, 0x2c};
    auto encrypted = client_->encrypt(msg);
    EXPECT_TRUE(!encrypted.empty());
    auto decrypted = server_->decrypt(encrypted);
    EXPECT_TRUE(decrypted.empty());

    encrypted = server_->encrypt(msg);
    EXPECT_TRUE(!encrypted.empty());
    decrypted = client_->decrypt(encrypted);
    EXPECT_TRUE(decrypted.empty());
}

TEST_F(AdbWifiPairingAuthTest, SamePasswords) {
    // Register same password and then exchange the msgs. The
    // encryption and decryption should succeed and have the same, unencrypted
    // values.
    setPassword({0xab, 0x47, 0x31, 0x66, 0x67, 0xfe});

    EXPECT_TRUE(client_->initCipher(server_->msg()));
    EXPECT_TRUE(server_->initCipher(client_->msg()));

    // encrypting/decrypting empty messages should return empty results.
    auto data = client_->encrypt({});
    EXPECT_TRUE(data.empty());
    data = client_->decrypt({});
    EXPECT_TRUE(data.empty());
    data = server_->encrypt({});
    EXPECT_TRUE(data.empty());
    data = server_->encrypt({});
    EXPECT_TRUE(data.empty());

    // Encrypted message from client can be decrypted by server
    std::vector<uint8_t> msg1{0x2f, 0x01, 0xed, 0xff, 0x53, 0x9a};
    auto encrypted = client_->encrypt(msg1);
    EXPECT_TRUE(!encrypted.empty());
    auto decrypted = server_->decrypt(encrypted);
    EXPECT_TRUE(!decrypted.empty());
    EXPECT_EQ(decrypted.size(), msg1.size());
    EXPECT_TRUE(memcmp(decrypted.data(), msg1.data(), msg1.size()) == 0);

    // Other way around as well
    std::vector<uint8_t> msg2{0x00, 0x67, 0x83, 0x00, 0xdd, 0x20, 0x00};
    encrypted = server_->encrypt(msg2);
    EXPECT_TRUE(!encrypted.empty());
    decrypted = client_->decrypt(encrypted);
    EXPECT_TRUE(!decrypted.empty());
    EXPECT_EQ(decrypted.size(), msg2.size());
    EXPECT_TRUE(memcmp(decrypted.data(), msg2.data(), msg2.size()) == 0);
}

TEST_F(AdbWifiPairingAuthTest, ServerMultiplePasswordGuesses) {
    std::vector<uint8_t> pswd{0xab, 0x47, 0x31, 0x66, 0x67, 0xfe};
    std::vector<uint8_t> bad1{0xaa, 0x47, 0x31, 0x66, 0x67, 0xfe};
    std::vector<uint8_t> bad2{0xab, 0x47, 0x31, 0x66, 0x67, 0xff};

    // Let's try to make the server do multiple guesses
    client_ = PairingAuth::create(PairingAuth::Role::Client,
                                       pswd);
    // Wrong password
    server_ = PairingAuth::create(PairingAuth::Role::Server,
                                       bad1);
    EXPECT_TRUE(client_->initCipher(server_->msg()));
    EXPECT_TRUE(server_->initCipher(client_->msg()));

    std::vector<uint8_t> msg{0x2f, 0x01, 0xed, 0xff, 0x53, 0x9a};
    // Encrypted messages can't be decrypted
    auto encrypted = client_->encrypt(msg);
    EXPECT_TRUE(!encrypted.empty());
    auto decrypted = server_->decrypt(encrypted);
    EXPECT_TRUE(decrypted.empty());
    encrypted = server_->encrypt(msg);
    EXPECT_TRUE(!encrypted.empty());
    decrypted = client_->decrypt(encrypted);
    EXPECT_TRUE(decrypted.empty());

    // Let's give server another bad password
    server_ = PairingAuth::create(PairingAuth::Role::Server,
                                       bad2);
    // client_ already initialized the cipher. Only one try per context.
    EXPECT_FALSE(client_->initCipher(server_->msg()));
    client_ = PairingAuth::create(PairingAuth::Role::Client,
                                       pswd);
    // On a new context, it should work
    EXPECT_TRUE(client_->initCipher(server_->msg()));
    EXPECT_TRUE(server_->initCipher(client_->msg()));

    // Encrypted messages still can't be decrypted
    encrypted = client_->encrypt(msg);
    EXPECT_TRUE(!encrypted.empty());
    decrypted = server_->decrypt(encrypted);
    EXPECT_TRUE(decrypted.empty());
    encrypted = server_->encrypt(msg);
    EXPECT_TRUE(!encrypted.empty());
    decrypted = client_->decrypt(encrypted);
    EXPECT_TRUE(decrypted.empty());

    // Now give server the good password
    server_ = PairingAuth::create(PairingAuth::Role::Server,
                                       pswd);
    EXPECT_FALSE(client_->initCipher(server_->msg()));
    client_ = PairingAuth::create(PairingAuth::Role::Client,
                                       pswd);
    // On a new context, it should work
    EXPECT_TRUE(client_->initCipher(server_->msg()));
    EXPECT_TRUE(server_->initCipher(client_->msg()));

    // The message can be decrypted on both ends
    encrypted = client_->encrypt(msg);
    EXPECT_TRUE(!encrypted.empty());
    decrypted = server_->decrypt(encrypted);
    EXPECT_TRUE(!decrypted.empty());
    EXPECT_EQ(decrypted.size(), msg.size());
    EXPECT_TRUE(memcmp(decrypted.data(), msg.data(), msg.size()) == 0);

    encrypted = server_->encrypt(msg);
    EXPECT_TRUE(!encrypted.empty());
    decrypted = client_->decrypt(encrypted);
    EXPECT_TRUE(!decrypted.empty());
    EXPECT_EQ(decrypted.size(), msg.size());
    EXPECT_TRUE(memcmp(decrypted.data(), msg.data(), msg.size()) == 0);
}

TEST_F(AdbWifiPairingAuthTest, ClientMultiplePasswordGuesses) {
    std::vector<uint8_t> pswd{0xab, 0x47, 0x31, 0x66, 0x67, 0xfe};
    std::vector<uint8_t> bad1{0xaa, 0x47, 0x31, 0x66, 0x67, 0xfe};
    std::vector<uint8_t> bad2{0xab, 0x47, 0x31, 0x66, 0x67, 0xff};

    // Let's try to make the client do multiple guesses
    server_ = PairingAuth::create(PairingAuth::Role::Server,
                                       pswd);
    // Wrong password
    client_ = PairingAuth::create(PairingAuth::Role::Client,
                                       bad1);
    EXPECT_TRUE(server_->initCipher(client_->msg()));
    EXPECT_TRUE(client_->initCipher(server_->msg()));

    std::vector<uint8_t> msg{0x2f, 0x01, 0xed, 0xff, 0x53, 0x9a};
    // Encrypted messages can't be decrypted
    auto encrypted = client_->encrypt(msg);
    EXPECT_TRUE(!encrypted.empty());
    auto decrypted = server_->decrypt(encrypted);
    EXPECT_TRUE(decrypted.empty());
    encrypted = server_->encrypt(msg);
    EXPECT_TRUE(!encrypted.empty());
    decrypted = client_->decrypt(encrypted);
    EXPECT_TRUE(decrypted.empty());

    // Let's give client another bad password
    client_ = PairingAuth::create(PairingAuth::Role::Client,
                                       bad2);
    // server_ already initialized the cipher. Only one try per context.
    EXPECT_FALSE(server_->initCipher(client_->msg()));
    server_ = PairingAuth::create(PairingAuth::Role::Server,
                                       pswd);
    // On a new context, it should work
    EXPECT_TRUE(server_->initCipher(client_->msg()));
    EXPECT_TRUE(client_->initCipher(server_->msg()));

    // Encrypted messages still can't be decrypted
    encrypted = client_->encrypt(msg);
    EXPECT_TRUE(!encrypted.empty());
    decrypted = server_->decrypt(encrypted);
    EXPECT_TRUE(decrypted.empty());
    encrypted = server_->encrypt(msg);
    EXPECT_TRUE(!encrypted.empty());
    decrypted = client_->decrypt(encrypted);
    EXPECT_TRUE(decrypted.empty());

    // Now give client the good password
    client_ = PairingAuth::create(PairingAuth::Role::Client,
                                       pswd);
    EXPECT_FALSE(server_->initCipher(client_->msg()));
    server_ = PairingAuth::create(PairingAuth::Role::Server,
                                       pswd);
    // On a new context, it should work
    EXPECT_TRUE(server_->initCipher(client_->msg()));
    EXPECT_TRUE(client_->initCipher(server_->msg()));

    // The message can be decrypted on both ends
    encrypted = client_->encrypt(msg);
    EXPECT_TRUE(!encrypted.empty());
    decrypted = server_->decrypt(encrypted);
    EXPECT_TRUE(!decrypted.empty());
    EXPECT_EQ(decrypted.size(), msg.size());
    EXPECT_TRUE(memcmp(decrypted.data(), msg.data(), msg.size()) == 0);

    encrypted = server_->encrypt(msg);
    EXPECT_TRUE(!encrypted.empty());
    decrypted = client_->decrypt(encrypted);
    EXPECT_TRUE(!decrypted.empty());
    EXPECT_EQ(decrypted.size(), msg.size());
    EXPECT_TRUE(memcmp(decrypted.data(), msg.data(), msg.size()) == 0);
}

}  // namespace pairing
}  // namespace adbwifi
