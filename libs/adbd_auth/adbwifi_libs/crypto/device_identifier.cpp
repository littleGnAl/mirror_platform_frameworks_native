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

#include "adbwifi/crypto/device_identifier.h"

#include <sys/stat.h>

#include <memory>
#include <random>

#include <adbwifi/sysdeps/sysdeps.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>

namespace adbwifi {
namespace crypto {

namespace {
const char kDeviceIdFilename[] = "adb_deviceid";
}

DeviceIdentifier::DeviceIdentifier(std::string_view keystore_path) :
    keystore_path_(keystore_path) {
    // Data partition may not be mounted yet. Wait until it's mounted otherwise
    // we might run into a situation where we override an already created key.
    if (!directoryExists(keystore_path_)) {
        LOG(WARNING) << "keystore [" << keystore_path_ << "] doesn't exist";
        return;
    }

    auto device_id = readUniqueDeviceIdFromFile(getDeviceIdPath());
    if (device_id.empty()) {
        LOG(INFO) << "No device id on disk";
        return;
    }

    strncpy(device_id_, device_id.data(), kDeviceIdNameSize);
    // TODO: make device_name_ persistent. Another protobuf to store device id
    // and name?
    device_name_ = "Pixel 3 XL";
    return;
}

std::string DeviceIdentifier::readUniqueDeviceIdFromFile(std::string_view filename) const {
    // See if we already saved the device id to adb_deviceid file
    LOG(INFO) << "Reading " << filename;
    std::string device_id;
    if (!android::base::ReadFileToString(std::string(filename.data()), &device_id)) {
        PLOG(ERROR) << "Couldn't read " << filename;
        return "";
    }
    LOG(INFO) << "Got deviceid=[" << device_id << "]";
    return device_id;
}

bool DeviceIdentifier::resetUniqueDeviceId(std::string_view guid) {
    return writeDeviceIdToFile(guid, getDeviceIdPath());
}

bool DeviceIdentifier::writeDeviceIdToFile(std::string_view id, std::string_view filename) {
    if (!android::base::WriteStringToFile(std::string(id.data()), std::string(filename.data()))) {
        PLOG(ERROR) << "Unable to write device id to " << filename;
        return false;
    }
    LOG(INFO) << "Wrote device id to " << filename;
    // Set permissions so adbd can read it later.
    chmod(filename.data(), S_IRUSR | S_IWUSR | S_IRGRP);
    return true;
}

std::string DeviceIdentifier::getDeviceName() const {
    return device_name_;
}

std::string DeviceIdentifier::getUniqueDeviceId() const {
    // Check if we have cached the ID yet
    if (device_id_[0] == '\0') {
        LOG(ERROR) << "No cached device id";
        return "";
    }
    LOG(ERROR) << "Returning cached device id";
    return device_id_;
}

std::string DeviceIdentifier::getDeviceIdPath() const {
    return keystore_path_ + OS_PATH_SEPARATOR + kDeviceIdFilename;
}

// static
bool DeviceIdentifier::directoryExists(std::string_view path) {
    struct stat sb;
    return stat(path.data(), &sb) != -1 && S_ISDIR(sb.st_mode);
}

}  // namespace crypto
}  // namespace adbwifi
