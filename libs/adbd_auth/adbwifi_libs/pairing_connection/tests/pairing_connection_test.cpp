/*
 * Copyright 2019 The Android Open Source Project
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

#include <condition_variable>
#include <mutex>
#include <thread>

#include <adbwifi/pairing/pairing_server.h>
#include <android-base/logging.h>
#include <gtest/gtest.h>

#include "pairing_client.h"

namespace adbwifi {
namespace pairing {

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

struct ServerDeleter {
    void operator()(PairingServerCtx* p) {
        pairing_server_destroy(p);
    }
};
using ServerPtr = std::unique_ptr<PairingServerCtx,
                                  ServerDeleter>;

static ServerPtr CreateServer(const std::vector<uint8_t>& pswd,
                              const PeerInfo& peer_info,
                              const std::vector<uint8_t>& cert,
                              const std::vector<uint8_t>& priv_key,
                              int port) {
    return ServerPtr(pairing_server_new(pswd.data(),
                                        pswd.size(),
                                        peer_info,
                                        cert.data(),
                                        cert.size(),
                                        priv_key.data(),
                                        priv_key.size(),
                                        port));
}
struct ResultWaiter {
    std::mutex mutex_;
    std::condition_variable cv_;
    std::optional<bool> is_valid_;
    PeerInfo peer_info_;

    static void ResultCallback(const PeerInfo* peer_info,
                               void* opaque) {
        ASSERT_NE(opaque, nullptr);
        LOG(INFO) << "Got resultcallback";
        auto* p = reinterpret_cast<ResultWaiter*>(opaque);
        {
            std::unique_lock<std::mutex> lock(p->mutex_);
            if (peer_info) {
                memcpy(&(p->peer_info_), peer_info, sizeof(PeerInfo));
            }
            p->is_valid_ = (peer_info != nullptr);
        }
        p->cv_.notify_one();
    }
};

class AdbWifiPairingConnectionTest : public testing::Test {
protected:
    virtual void SetUp() override {
    }

    virtual void TearDown() override {
    }

    void initPairing(const std::vector<uint8_t> server_pswd,
                     const std::vector<uint8_t> client_pswd) {
        std::vector<uint8_t> cert;
        std::vector<uint8_t> key;
        // Include the null-byte as well.
        cert.assign(reinterpret_cast<const uint8_t*>(kTestServerCert.data()),
                    reinterpret_cast<const uint8_t*>(kTestServerCert.data()) + kTestServerCert.size() + 1);
        key.assign(reinterpret_cast<const uint8_t*>(kTestServerPrivKey.data()),
                   reinterpret_cast<const uint8_t*>(kTestServerPrivKey.data()) + kTestServerPrivKey.size() + 1);
        server_ = CreateServer(server_pswd,
                               server_info_,
                               cert,
                               key,
                               kDefaultPairingPort);
        cert.assign(reinterpret_cast<const uint8_t*>(kTestClientCert.data()),
                    reinterpret_cast<const uint8_t*>(kTestClientCert.data()) + kTestClientCert.size() + 1);
        key.assign(reinterpret_cast<const uint8_t*>(kTestClientPrivKey.data()),
                   reinterpret_cast<const uint8_t*>(kTestClientPrivKey.data()) + kTestClientPrivKey.size() + 1);
        client_ = PairingClient::create(client_pswd,
                                        client_info_,
                                        cert,
                                        key,
                                        "127.0.0.1");
    }

    ServerPtr createServer(const std::vector<uint8_t>& pswd) {
        std::vector<uint8_t> cert;
        std::vector<uint8_t> key;
        // Include the null-byte as well.
        cert.assign(reinterpret_cast<const uint8_t*>(kTestServerCert.data()),
                    reinterpret_cast<const uint8_t*>(kTestServerCert.data()) + kTestServerCert.size() + 1);
        key.assign(reinterpret_cast<const uint8_t*>(kTestServerPrivKey.data()),
                   reinterpret_cast<const uint8_t*>(kTestServerPrivKey.data()) + kTestServerPrivKey.size() + 1);
        return CreateServer(pswd,
                            server_info_,
                            cert,
                            key,
                            kDefaultPairingPort);
    }

    std::unique_ptr<PairingClient> createClient(const std::vector<uint8_t> pswd) {
        std::vector<uint8_t> cert;
        std::vector<uint8_t> key;
        // Include the null-byte as well.
        cert.assign(reinterpret_cast<const uint8_t*>(kTestClientCert.data()),
                    reinterpret_cast<const uint8_t*>(kTestClientCert.data()) + kTestClientCert.size() + 1);
        key.assign(reinterpret_cast<const uint8_t*>(kTestClientPrivKey.data()),
                   reinterpret_cast<const uint8_t*>(kTestClientPrivKey.data()) + kTestClientPrivKey.size() + 1);
        return PairingClient::create(pswd,
                                     client_info_,
                                     cert,
                                     key,
                                     "127.0.0.1");
    }

    ServerPtr server_;
    const PeerInfo server_info_ = {
          .info = "my_server_info",
    };
    std::unique_ptr<PairingClient> client_;
    const PeerInfo client_info_ = {
          .info = "my_client_info",
    };
};

TEST_F(AdbWifiPairingConnectionTest, ServerCreation) {
    // All parameters bad
    ASSERT_DEATH({
        auto server = CreateServer({}, {}, {}, {}, -1);
    }, "");
    // Bad password
    ASSERT_DEATH({
        auto server = CreateServer({}, server_info_, {0x01}, {0x01}, -1);
    }, "");
    // Bad peer_info
    ASSERT_DEATH({
        auto server = CreateServer({0x01}, {}, {0x01}, {0x01}, -1);
    }, "");
    // Bad certificate
    ASSERT_DEATH({
        auto server = CreateServer({0x01}, server_info_, {}, {0x01}, -1);
    }, "");
    // Bad private key
    ASSERT_DEATH({
        auto server = CreateServer({0x01}, server_info_, {0x01}, {}, -1);
    }, "");
    // Bad port
    ASSERT_DEATH({
        auto server = CreateServer({0x01}, server_info_, {0x01}, {0x01}, -1);
    }, "");
    // Valid params
    auto server = CreateServer({0x01}, server_info_, {0x01}, {0x01}, 7776);
    EXPECT_NE(nullptr, server);
}

TEST_F(AdbWifiPairingConnectionTest, ClientCreation) {
    // All parameters bad
    ASSERT_DEATH({
    auto client = PairingClient::create({}, client_info_, {}, {}, "");
    }, "");
    // Bad password
    ASSERT_DEATH({
    auto client = PairingClient::create({}, client_info_, {0x01}, {0x01}, "127.0.0.1");
    }, "");
    // Bad peer_info
    ASSERT_DEATH({
    auto client = PairingClient::create({0x01}, {}, {0x01}, {0x01}, "127.0.0.1");
    }, "");
    // Bad certificate
    ASSERT_DEATH({
    auto client = PairingClient::create({0x01}, client_info_, {}, {0x01}, "127.0.0.1");
    }, "");
    // Bad private key
    ASSERT_DEATH({
    auto client = PairingClient::create({0x01}, client_info_, {0x01}, {}, "127.0.0.1");
    }, "");
    // Bad ip address
    ASSERT_DEATH({
    auto client = PairingClient::create({0x01}, client_info_, {0x01}, {0x01}, "");
    }, "");
    // Valid params
    auto client = PairingClient::create({0x01}, client_info_, {0x01}, {0x01}, "127.0.0.1");
    EXPECT_NE(nullptr, client);
}

TEST_F(AdbWifiPairingConnectionTest, SmokeValidPairing) {
    std::vector<uint8_t> pswd{0x01, 0x03, 0x05, 0x07};
    initPairing(pswd, pswd);

    // Start the server
    ResultWaiter server_waiter;
    std::unique_lock<std::mutex> server_lock(server_waiter.mutex_);
    ASSERT_TRUE(pairing_server_start(server_.get(), server_waiter.ResultCallback, &server_waiter));

    // Start the client
    ResultWaiter client_waiter;
    std::unique_lock<std::mutex> client_lock(client_waiter.mutex_);
    ASSERT_TRUE(client_->start(client_waiter.ResultCallback, &client_waiter));
    client_waiter.cv_.wait(client_lock, [&]() { return client_waiter.is_valid_.has_value(); });
    ASSERT_TRUE(*(client_waiter.is_valid_));
    ASSERT_EQ(strlen(client_waiter.peer_info_.info), strlen(server_info_.info));
    EXPECT_EQ(memcmp(client_waiter.peer_info_.info, server_info_.info, strlen(server_info_.info)), 0);

    // Kill server if the pairing failed, since server only shuts down when
    // it gets a valid pairing.
    if (!client_waiter.is_valid_) {
        server_lock.unlock();
        server_.reset();
    } else {
        server_waiter.cv_.wait(server_lock, [&]() { return server_waiter.is_valid_.has_value(); });
        ASSERT_TRUE(*(server_waiter.is_valid_));
        ASSERT_EQ(strlen(server_waiter.peer_info_.info), strlen(client_info_.info));
        EXPECT_EQ(memcmp(server_waiter.peer_info_.info, client_info_.info, strlen(client_info_.info)), 0);
    }
}

TEST_F(AdbWifiPairingConnectionTest, CancelPairing) {
    std::vector<uint8_t> pswd{0x01, 0x03, 0x05, 0x07};
    std::vector<uint8_t> pswd2{0x01, 0x03, 0x05, 0x06};
    initPairing(pswd, pswd2);

    // Start the server
    ResultWaiter server_waiter;
    std::unique_lock<std::mutex> server_lock(server_waiter.mutex_);
    ASSERT_TRUE(pairing_server_start(server_.get(), server_waiter.ResultCallback, &server_waiter));

    // Start the client. Client should fail to pair
    ResultWaiter client_waiter;
    std::unique_lock<std::mutex> client_lock(client_waiter.mutex_);
    ASSERT_TRUE(client_->start(client_waiter.ResultCallback, &client_waiter));
    client_waiter.cv_.wait(client_lock, [&]() { return client_waiter.is_valid_.has_value(); });
    ASSERT_FALSE(*(client_waiter.is_valid_));

    // Kill the server. We should still receive the callback with no valid
    // pairing.
    server_lock.unlock();
    server_.reset();
    server_lock.lock();
    ASSERT_TRUE(server_waiter.is_valid_.has_value());
    EXPECT_FALSE(*(server_waiter.is_valid_));
}

TEST_F(AdbWifiPairingConnectionTest, MultipleClientsAllFail) {
    std::vector<uint8_t> pswd{0x01, 0x03, 0x05, 0x07};
    std::vector<uint8_t> pswd2{0x01, 0x03, 0x05, 0x06};

    // Start the server
    auto server = createServer(pswd);
    ResultWaiter server_waiter;
    std::unique_lock<std::mutex> server_lock(server_waiter.mutex_);
    ASSERT_TRUE(pairing_server_start(server.get(), server_waiter.ResultCallback, &server_waiter));

    // Start multiple clients, all with bad passwords
    int test_num_clients = 5;
    int num_clients_done = 0;
    std::mutex global_clients_mutex;
    std::unique_lock<std::mutex> global_clients_lock(global_clients_mutex);
    std::condition_variable global_cv_;
    for (int i = 0; i < test_num_clients; ++i) {
        std::thread([&]() {
            auto client = createClient(pswd2);
            ResultWaiter client_waiter;
            std::unique_lock<std::mutex> client_lock(client_waiter.mutex_);
            ASSERT_TRUE(client->start(client_waiter.ResultCallback, &client_waiter));
            client_waiter.cv_.wait(client_lock, [&]() { return client_waiter.is_valid_.has_value(); });
            ASSERT_FALSE(*(client_waiter.is_valid_));
            {
                std::lock_guard<std::mutex> global_lock(global_clients_mutex);
                ++num_clients_done;
            }
            global_cv_.notify_one();
        }).detach();
    }

    global_cv_.wait(global_clients_lock, [&]() { return num_clients_done == test_num_clients; });
    server_lock.unlock();
    server.reset();
    server_lock.lock();
    ASSERT_TRUE(server_waiter.is_valid_.has_value());
    EXPECT_FALSE(*(server_waiter.is_valid_));
}

TEST_F(AdbWifiPairingConnectionTest, MultipleClientsOnePass) {
    // Send multiple clients with bad passwords, but send the last one with the
    // correct password.
    std::vector<uint8_t> pswd{0x01, 0x03, 0x05, 0x07};
    std::vector<uint8_t> pswd2{0x01, 0x03, 0x05, 0x06};

    // Start the server
    auto server = createServer(pswd);
    ResultWaiter server_waiter;
    std::unique_lock<std::mutex> server_lock(server_waiter.mutex_);
    ASSERT_TRUE(pairing_server_start(server.get(), server_waiter.ResultCallback, &server_waiter));

    // Start multiple clients, all with bad passwords
    int test_num_clients = 5;
    int num_clients_done = 0;
    std::mutex global_clients_mutex;
    std::unique_lock<std::mutex> global_clients_lock(global_clients_mutex);
    std::condition_variable global_cv_;
    for (int i = 0; i < test_num_clients; ++i) {
        std::thread([&, i]() {
            bool good_client = (i == (test_num_clients - 1));
            auto client = createClient((good_client ? pswd : pswd2));
            ResultWaiter client_waiter;
            std::unique_lock<std::mutex> client_lock(client_waiter.mutex_);
            ASSERT_TRUE(client->start(client_waiter.ResultCallback, &client_waiter));
            client_waiter.cv_.wait(client_lock, [&]() { return client_waiter.is_valid_.has_value(); });
            if (good_client) {
                ASSERT_TRUE(*(client_waiter.is_valid_));
                ASSERT_EQ(strlen(client_waiter.peer_info_.info),
                          strlen(server_info_.info));
                EXPECT_EQ(memcmp(client_waiter.peer_info_.info, server_info_.info,
                                 strlen(server_info_.info)), 0);
            } else {
                ASSERT_FALSE(*(client_waiter.is_valid_));
            }
            {
                std::lock_guard<std::mutex> global_lock(global_clients_mutex);
                ++num_clients_done;
            }
            global_cv_.notify_one();
        }).detach();
    }

    global_cv_.wait(global_clients_lock, [&]() { return num_clients_done == test_num_clients; });
    server_waiter.cv_.wait(server_lock, [&]() { return server_waiter.is_valid_.has_value(); });
    ASSERT_TRUE(*(server_waiter.is_valid_));
    ASSERT_EQ(strlen(server_waiter.peer_info_.info), strlen(client_info_.info));
    EXPECT_EQ(memcmp(server_waiter.peer_info_.info, client_info_.info, strlen(client_info_.info)), 0);
}

}  // namespace pairing
}  // namespace adbwifi
