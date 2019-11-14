/*
 * Copyright (C) 2019 The Android Open Source Project
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

#pragma once

#include <string>

#include "proto/device_identifier.pb.h"

namespace adbwifi {
namespace crypto {

class DeviceIdentifier {
public:
    // Will try to read the device id from <keystore_path>/adb_deviceid. If the
    // file doesn't exist or is empty, |setUniqueDeviceId| and |setDeviceName|
    // must be called to set the device id and device name, respectively.
    explicit DeviceIdentifier(std::string_view keystore_path);
    virtual ~DeviceIdentifier();

    // Initializes the device id. If none exists, it will create a new one.
    // Returns the name of the device.
    std::string getDeviceName() const;
    // Resets the device's human-readable name to |name| and writes to the
    // adb_deviceid file. True if successful, false otherwise.
    bool setDeviceName(std::string_view name);
    // Returns the unique id of the device. If one does not exist, one needs to
    // be created by calling |resetUniqueDeviceId|.
    std::string getUniqueDeviceId() const;
    // Sets the device's unique identifier to |guid| and writes to the
    // adb_deviceid file. True if successful, false otherwise.
    bool setUniqueDeviceId(std::string_view guid);

private:

    bool readUniqueDeviceIdFromFile(std::string_view filename,
                                    adbwifi::proto::DeviceIdentifier& pb_id) const;
    bool writeDeviceIdToFile(std::string_view filename,
                             const adbwifi::proto::DeviceIdentifier& pb_id);
    std::string getDeviceIdPath() const;

    std::string keystore_path_;
    adbwifi::proto::DeviceIdentifier pb_id_;
};  // DeviceIdentifier

}  // namespace crypto
}  // namespace adbwifi
