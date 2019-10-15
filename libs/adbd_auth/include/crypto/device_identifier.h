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

class DeviceIdentifier {
public:
    explicit DeviceIdentifier(std::string_view keystore_path);

    // Initializes the device id. If none exists, it will create a new one.
    bool init();
    // Returns the name of the device.
    std::string getDeviceName() const;
    // Returns the unique id of the device. If one does not exist, it will be
    // created and stored in the adb_deviceid file.
    std::string getUniqueDeviceId() const;

    virtual ~DeviceIdentifier() = default;

private:
    static bool directoryExists(std::string_view path);

    std::string createUniqueDeviceId();
    bool writeDeviceIdToFile(std::string_view id, std::string_view filename);
    std::string getDeviceIdPath() const;
    std::string getHostName() const;
    std::string getUserName() const;

    std::string keystore_path_;
    static constexpr size_t kDeviceIdSize = 128;
    // The amount of space reserved for the random part and the name part of the
    // device ID.
    static constexpr size_t kDeviceIdRandomSize = 64;
    static constexpr size_t kDeviceIdNameSize = kDeviceIdSize - kDeviceIdRandomSize - 2;
    char device_id_[kDeviceIdSize] = { 0 };
};  // DeviceIdentifier
