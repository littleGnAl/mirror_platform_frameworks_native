/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
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

#include <gtest/gtest.h>

#include <unordered_map>

#include <adbwifi/crypto/device_identifier.h>
#include <adbwifi/crypto/key_store.h>
#include <android-base/file.h>

namespace adbwifi {
namespace crypto {

class AdbWifiKeyStoreTest : public testing::Test {
protected:
    virtual void SetUp() override {
        peers_["PeerGUID1"] = KeyStore::makePeerInfo(
                "PeerGUID1", "PeerName1", "PeerCert1");
        peers_["PeerGUID2"] = KeyStore::makePeerInfo(
                "PeerGUID2", "PeerName2", "PeerCert2");
    }

    virtual void TearDown() override {
        persist_dir_.reset();
    }

    // This just generates the device_id, and adds in peers_.
    void presetKeystore() {
        persist_dir_.reset(new TemporaryDir());
        DeviceIdentifier device_id(persist_dir_->path);
        device_id.setUniqueDeviceId(device_guid_);
        device_id.setDeviceName(device_name_);
        auto key_store = KeyStore::create(persist_dir_->path);
        for (const auto& peer : peers_) {
            key_store->storePeerInfo(peer.second);
        }
    }

    std::unique_ptr<TemporaryDir> persist_dir_;
    std::unordered_map<std::string, KeyStore::PeerInfo> peers_;
    static const char device_guid_[];
    static const char device_name_[];
};

// static
const char AdbWifiKeyStoreTest::device_guid_[] = "MyDeviceGuid123";
const char AdbWifiKeyStoreTest::device_name_[] = "MyDeviceName123";

TEST_F(AdbWifiKeyStoreTest, Smoke) {
    TemporaryDir dir;

    // This should fail because the device identifier has not been created yet.
    auto key_store = KeyStore::create(dir.path);
    ASSERT_EQ(key_store.get(), nullptr);

    // Create the device identifier
    DeviceIdentifier device_id(dir.path);
    device_id.setUniqueDeviceId(device_guid_);
    device_id.setDeviceName(device_name_);

    // Now KeyStore can be created.
    key_store = KeyStore::create(dir.path);

    // All of our info should be non-empty.
    auto device_info = key_store->getDeviceInfo();
    ASSERT_TRUE(device_info.has_value());
    auto [guid, name, cert, priv_key] = std::move(*device_info);
    EXPECT_FALSE(guid.empty());
    EXPECT_STREQ(guid.c_str(), device_guid_);
    EXPECT_FALSE(name.empty());
    EXPECT_FALSE(cert.empty());
    EXPECT_FALSE(priv_key.empty());

    // The keystore should be empty.
    EXPECT_EQ(key_store->size(), 0);

    // Add the PeerInfos
    for (const auto& peer : peers_) {
        key_store->storePeerInfo(peer.second);
    }

    // The keystore should have those peers now.
    EXPECT_EQ(key_store->size(), peers_.size());

    // Check each peer stored.
    for (int i = 0; i < key_store->size(); ++i) {
        auto ks_peer = (*key_store)[i];
        auto my_peer = peers_.find(ks_peer.first);
        ASSERT_NE(my_peer, peers_.end());
        auto& [ks_guid, ks_name, ks_cert] = *(ks_peer.second);
        auto& [guid, name, cert] = *(my_peer->second);
        EXPECT_STREQ(guid.c_str(), ks_guid.c_str());
        EXPECT_STREQ(name.c_str(), ks_name.c_str());
        EXPECT_STREQ(cert.c_str(), ks_cert.c_str());
    }
    // Also try using getPeerInfo API
    for (const auto& peer : peers_) {
        auto ks_peer = key_store->getPeerInfo(peer.first);
        ASSERT_NE(ks_peer, std::nullopt);
        auto& [ks_guid, ks_name, ks_cert] = *ks_peer;
        auto& [guid, name, cert] = *(peer.second);
        EXPECT_STREQ(guid.c_str(), ks_guid.c_str());
        EXPECT_STREQ(name.c_str(), ks_name.c_str());
        EXPECT_STREQ(cert.c_str(), ks_cert.c_str());
    }

    // Try to find/remove a non-existent peer
    {
        auto peer = key_store->getPeerInfo("IDontExistGuid");
        EXPECT_FALSE(peer.has_value());
        EXPECT_FALSE(key_store->removePeerInfo("IDontExistGuid"));
    }

    // Remove a valid PeerInfo
    {
        auto [guid, name, cert] = *(peers_.begin()->second);
        peers_.erase(guid);
        EXPECT_TRUE(key_store->removePeerInfo(guid));
        EXPECT_EQ(key_store->size(), peers_.size());
    }

    // Validate that all non-removed peers are still there.
    for (const auto& peer : peers_) {
        auto ks_peer = key_store->getPeerInfo(peer.first);
        ASSERT_NE(ks_peer, std::nullopt);
        auto& [ks_guid, ks_name, ks_cert] = *ks_peer;
        auto& [guid, name, cert] = *(peer.second);
        EXPECT_STREQ(guid.c_str(), ks_guid.c_str());
        EXPECT_STREQ(name.c_str(), ks_name.c_str());
        EXPECT_STREQ(cert.c_str(), ks_cert.c_str());
    }
}

TEST_F(AdbWifiKeyStoreTest, LoadKeyStoreFromFile) {
    // This creates a keystore with peers.
    presetKeystore();
    // On the second instantiation of keystore, it should load from file, and we
    // should have the same DeviceInfo and PeerInfos.
    auto key_store = KeyStore::create(persist_dir_->path);

    // All of our info should be non-empty.
    auto device_info = key_store->getDeviceInfo();
    ASSERT_TRUE(device_info.has_value());
    auto [guid, name, cert, priv_key] = std::move(*device_info);
    EXPECT_FALSE(guid.empty());
    EXPECT_STREQ(guid.c_str(), device_guid_);
    EXPECT_FALSE(name.empty());
    EXPECT_FALSE(cert.empty());
    EXPECT_FALSE(priv_key.empty());

    ASSERT_EQ(key_store->size(), peers_.size());

    // Validate that all non-removed peers are still there.
    for (const auto& peer : peers_) {
        auto ks_peer = key_store->getPeerInfo(peer.first);
        ASSERT_NE(ks_peer, std::nullopt);
        auto& [ks_guid, ks_name, ks_cert] = *ks_peer;
        auto& [guid, name, cert] = *(peer.second);
        EXPECT_STREQ(guid.c_str(), ks_guid.c_str());
        EXPECT_STREQ(name.c_str(), ks_name.c_str());
        EXPECT_STREQ(cert.c_str(), ks_cert.c_str());
    }
}

}  // namespace crypto
}  // namespace adbwifi
