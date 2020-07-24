/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include <fuzzer/FuzzedDataProvider.h>
#include <input/KeyCharacterMap.h>

#include <filesystem>
#include <optional>
#include <string>

static const std::string FILENAME_PREFIX = "/keycharactermapXXXXXXXXX";

android::KeyCharacterMap::Format getFormat(uint8_t option) {
    switch (option) {
        case 0: {
            return android::KeyCharacterMap::FORMAT_BASE;
        }
        case 1: {
            return android::KeyCharacterMap::FORMAT_OVERLAY;
        }
        default: {
            return android::KeyCharacterMap::FORMAT_ANY;
        }
    }
}

std::optional<std::string> generateRandomKeyCharacterMap(const uint8_t* data, size_t size) {
    // Suitable path of directory for creation of temp files in the filesystem
    std::string tempFileDir = std::filesystem::temp_directory_path();
    std::string tempFilePath = tempFileDir + FILENAME_PREFIX;
    size_t tempFilePathLength = tempFilePath.length();

    char filePath[tempFilePathLength];

    strncpy(filePath, tempFilePath.c_str(),
            tempFilePathLength); // mkstemp requires non-const char array

    int fd = mkstemp(filePath);

    if (fd < 0) {
        return std::nullopt;
    }

    write(fd, data, size);
    close(fd);

    return std::string(filePath);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // 3 different formats available.
    android::KeyCharacterMap::Format format = getFormat(fdp.ConsumeIntegralInRange<uint8_t>(0, 2));

    std::optional<std::string> filePath = generateRandomKeyCharacterMap(data, size);

    // if File Creation fails
    if (filePath == std::nullopt) {
        return 0;
    }

    android::sp<android::KeyCharacterMap> m;
    android::KeyCharacterMap::load(filePath.value(), format, &m);

    remove(filePath.value().c_str());

    return 0;
}