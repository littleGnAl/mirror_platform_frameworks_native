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
#include <android-base/file.h>

namespace adbwifi {
namespace crypto {

class AdbWifiDeviceIdentifierTest : public testing::Test {
protected:
    virtual void SetUp() override {
    }

    virtual void TearDown() override {
        persist_dir_.reset();
    }

    // This just generates the device_id, and adds in peers_.
    void presetDeviceId() {
        persist_dir_.reset(new TemporaryDir());
        DeviceIdentifier device_id(persist_dir_->path);
        device_id.setUniqueDeviceId(device_guid_);
        device_id.setDeviceName(device_name_);
    }

    std::unique_ptr<TemporaryDir> persist_dir_;
    static const char device_guid_[];
    static const char device_name_[];
};

// static
const char AdbWifiDeviceIdentifierTest::device_guid_[] = "MyDeviceGuid123";
const char AdbWifiDeviceIdentifierTest::device_name_[] = "MyDeviceName123";

TEST_F(AdbWifiDeviceIdentifierTest, Smoke) {
    TemporaryDir dir;

    // Create the device identifier
    DeviceIdentifier device_id(dir.path);

    // The device name and guid should be empty.
    EXPECT_TRUE(device_id.getDeviceName().empty());
    EXPECT_TRUE(device_id.getUniqueDeviceId().empty());

    device_id.setUniqueDeviceId(device_guid_);
    // Now we should have the device id set.
    EXPECT_FALSE(device_id.getUniqueDeviceId().empty());
    EXPECT_STREQ(device_id.getUniqueDeviceId().c_str(), device_guid_);

    device_id.setDeviceName(device_name_);
    // Now we should have the device name set.
    EXPECT_FALSE(device_id.getDeviceName().empty());
    EXPECT_STREQ(device_id.getDeviceName().c_str(), device_name_);
}

TEST_F(AdbWifiDeviceIdentifierTest, LoadDeviceIdFromFile) {
    // This creates the device id which should be stored in the file
    // (adb_deviceid). Instantiating another DeviceIdentifier instance should
    // load it from file.
    presetDeviceId();
    DeviceIdentifier device_id(persist_dir_->path);

    // The device name should be set.
    EXPECT_FALSE(device_id.getDeviceName().empty());
    EXPECT_STREQ(device_id.getDeviceName().c_str(), device_name_);

    // The device id should be set.
    EXPECT_FALSE(device_id.getUniqueDeviceId().empty());
    EXPECT_STREQ(device_id.getUniqueDeviceId().c_str(), device_guid_);
}

}  // namespace crypto
}  // namespace adbwifi
