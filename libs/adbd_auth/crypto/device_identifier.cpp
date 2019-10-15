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

#include "crypto/device_identifier.h"

#include <sys/stat.h>

#include <memory>
#include <random>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include "compat/msvc-posix.h"

namespace {
const char kDeviceIdFilename[] = "adb_deviceid";
}

DeviceIdentifier::DeviceIdentifier(std::string_view keystore_path) :
    keystore_path_(keystore_path) { }

bool DeviceIdentifier::init() {
    // Data partition may not be mounted yet. Wait until it's mounted otherwise
    // we might run into a situation where we override an already created key.
    if (!directoryExists(keystore_path_)) {
        LOG(WARNING) << "keystore [" << keystore_path_ << "] doesn't exist";
        return false;
    }

    auto device_id = readUniqueDeviceIdFromFile(getDeviceIdPath());
    if (device_id.empty()) {
        // Create a new GUID.
        LOG(INFO) << "No device id on disk, generating";
        device_id = createUniqueDeviceId();
        // Write the new GUID to file.
        if (!writeDeviceIdToFile(device_id, getDeviceIdPath())) {
            return false;
        }
    }

    strncpy(device_id_, device_id.data(), kDeviceIdNameSize);
    return true;
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

std::string DeviceIdentifier::createUniqueDeviceId() const {
#if defined(__ANDROID__)
    // Use the serial number (adb-<serialno>)
    std::string guid = "adb-";
    // CTS tests check for the serialno to be between 6-20 characters
    // (https://android.googlesource.com/platform/cts/+/master/tests/tests/os/src/android/os/cts/BuildTest.java#224).
    // We should be okay regarding the size.
    guid += android::base::GetProperty("ro.serialno", "unidentified");
    return guid;
#else
    char id[kDeviceIdSize];
    std::string hostname = getHostName();
    strncpy(id, hostname.c_str(), kDeviceIdNameSize);
    id[kDeviceIdNameSize] = '\0';
    strcat(id, "-");

    char randomPart[kDeviceIdRandomSize];
    std::random_device rd;
    std::mt19937 mt(rd());
    // Generate values starting with zero and then up to enough to cover numeric
    // digits, small letters and capital letters (26 each).
    std::uniform_int_distribution<uint8_t> dist(0, 61);

    for (size_t i = 0; i < sizeof(randomPart) - 1; ++i) {
        uint8_t value = dist(mt);
        if (value < 10) {
            randomPart[i] = '0' + value;
        } else if (value < 36) {
            randomPart[i] = 'A' + (value - 10);
        } else {
            randomPart[i] = 'a' + (value - 36);
        }
    }
    randomPart[sizeof(randomPart) - 1] = '\0';
    strcat(id, randomPart);
    return id;
#endif
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
    return getUserName() + "@" + getHostName();
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

std::string DeviceIdentifier::getHostName() const {
    std::string hostname;

    const char* hostnamePtr = getenv("HOSTNAME");
    if (hostnamePtr && *hostnamePtr != '\0') {
        hostname = hostnamePtr;
    } else {
        char buffer[1024];
        if (my_gethostname(buffer, sizeof(buffer)) == 0) {
            hostname = buffer;
        } else {
            hostname = "unknown";
        }
    }
    return hostname;
}

std::string DeviceIdentifier::getUserName() const {
    std::string username;

    const char* loginPtr = getenv("LOGNAME");
    if (loginPtr && *loginPtr != '\0') {
        username = loginPtr;
    } else {
        char buffer[1024];
        if (my_getlogin_r(buffer, sizeof(buffer)) == 0) {
            username = buffer;
        } else {
            username = "unknown";
        }
    }
    return username;
}

// static
bool DeviceIdentifier::directoryExists(std::string_view path) {
    struct stat sb;
    return stat(path.data(), &sb) != -1 && S_ISDIR(sb.st_mode);
}
