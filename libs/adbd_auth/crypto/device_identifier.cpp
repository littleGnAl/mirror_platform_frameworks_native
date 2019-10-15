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

#include <android-base/logging.h>
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
        return false;
    }

    auto device_id = createUniqueDeviceId();
    if (device_id.empty()) {
        return false;
    }

    strncpy(device_id_, device_id.data(), kDeviceIdNameSize);
    if (!writeDeviceIdToFile(device_id_, getDeviceIdPath())) {
        device_id_[0] = '\0';
        return false;
    }
    return true;
}

std::string DeviceIdentifier::createUniqueDeviceId() {
    // See if we already saved the device id to adb_deviceid file
    char id[kDeviceIdSize];
    std::string path = getDeviceIdPath();
    std::unique_ptr<FILE, decltype(&fclose)> file(fopen(path.c_str(), "r"),
                                                  &fclose);
    if (file) {
        size_t bytes = fread(id, 1, sizeof(id), file.get());
        if (!ferror(file.get())) {
            id[std::min(bytes, sizeof(id) - 1)] = '\0';
            LOG(INFO) << "Found device id on disk '" << id << "'";
            return id;
        }
    }

    LOG(INFO) << "No device id on disk, generating";
    // If we haven't stored it we need to generate an ID
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
}

bool DeviceIdentifier::writeDeviceIdToFile(std::string_view id, std::string_view filename) {
    std::unique_ptr<FILE, decltype(&fclose)> file(fopen(filename.data(), "w"),
                                                  &fclose);
    if (file) {
        if (fwrite(id.data(), id.size(), 1, file.get()) != 1) {
            // Unable to write, return the ID for now but it will not persist
            // across boots.
            LOG(ERROR) << "Unable to store device ID: " << strerror(errno);
            return false;
        }
    } else {
        LOG(ERROR) << "Unable to open device ID file for writing: " << strerror(errno);
        return false;
    }
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
