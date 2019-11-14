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

#include <fstream>
#include <memory>

#include <adbwifi/sysdeps/sysdeps.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/properties.h>

#include "adbwifi/crypto/file_utils.h"

namespace adbwifi {
namespace crypto {

namespace {
const char kDeviceIdFilename[] = "adb_deviceid";
}

DeviceIdentifier::DeviceIdentifier(std::string_view keystore_path) :
    keystore_path_(keystore_path) {
    // Data partition may not be mounted yet. Wait until it's mounted otherwise
    // we might run into a situation where we override an already created key.
    if (!DirectoryExists(keystore_path_)) {
        LOG(WARNING) << "keystore [" << keystore_path_ << "] doesn't exist";
        return;
    }

    if (!readUniqueDeviceIdFromFile(getDeviceIdPath(), pb_id_)) {
        LOG(INFO) << "Unable to read " << kDeviceIdFilename;
        return;
    }
}

DeviceIdentifier::~DeviceIdentifier() {
    // Defined here instead of in the header because of protobuf compilation errors.
}

bool DeviceIdentifier::readUniqueDeviceIdFromFile(std::string_view filename,
                                                  adbwifi::proto::DeviceIdentifier& pb_id) const {
    // See if we already saved the device id to adb_deviceid file
    std::ifstream file(filename, std::ios::binary);
    if (!file) {
        // Not an error. It just means there's no device id yet.
        LOG(INFO) << filename << " not found";
        return false;
    }

    // Read the file contents into the protobuf.
    if (!pb_id.ParseFromIstream(&file)) {
        // The file may have been corrupted. Let's just delete it, otherwise,
        // we'll never be able to read/write to it.
        LOG(ERROR) << filename << " may be corrupted. Deleting it.";
        sysdeps::adb_unlink(filename.data());
        return false;
    }
    return true;
}

bool DeviceIdentifier::setDeviceName(std::string_view name) {
    pb_id_.set_name(std::string(name));
    return writeDeviceIdToFile(getDeviceIdPath(), pb_id_);
}

bool DeviceIdentifier::setUniqueDeviceId(std::string_view guid) {
    pb_id_.set_guid(std::string(guid));
    return writeDeviceIdToFile(getDeviceIdPath(), pb_id_);
}

bool DeviceIdentifier::writeDeviceIdToFile(std::string_view filename,
                                           const adbwifi::proto::DeviceIdentifier& pb_id) {
    std::unique_ptr<TemporaryFile> temp_file(new TemporaryFile(keystore_path_));
    if (temp_file->fd == -1) {
        PLOG(ERROR) << "Failed to open '" << temp_file->path << "' for writing";
        return false;
    }
    // Write the protobuf to file.
    if (!pb_id.SerializeToFileDescriptor(temp_file->fd)) {
        LOG(ERROR) << "Unable to write DeviceIdentifier out.";
        return false;
    }

    temp_file->DoNotRemove();
    std::string temp_file_name(temp_file->path);
    temp_file.reset();

    // Replace the old file with the new one.
    if (!SafeReplaceFile(filename, temp_file_name)) {
        LOG(ERROR) << "Failed to replace " << filename;
        // Remove the temp file
        sysdeps::adb_unlink(temp_file_name.c_str());
        return false;
    }

    // Set permissions so adbd can read it later.
    chmod(filename.data(), S_IRUSR | S_IWUSR | S_IRGRP);
    return true;
}

std::string DeviceIdentifier::getDeviceName() const {
    return pb_id_.name();
}

std::string DeviceIdentifier::getUniqueDeviceId() const {
    return pb_id_.guid();
}

std::string DeviceIdentifier::getDeviceIdPath() const {
    return keystore_path_ + OS_PATH_SEPARATOR + kDeviceIdFilename;
}

}  // namespace crypto
}  // namespace adbwifi
