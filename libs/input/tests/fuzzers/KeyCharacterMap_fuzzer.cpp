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

static const char TEMP_FILE_NAME[] = "/data/local/tmp/keycharactermapXXXXXXXXX";
static const size_t TEMP_FILE_NAME_LEN = sizeof(TEMP_FILE_NAME);

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

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    FuzzedDataProvider fdp(data, size);

    // Three different formats available.
    android::KeyCharacterMap::Format format = getFormat(fdp.ConsumeIntegralInRange<uint8_t>(0, 2));

    char filePath[TEMP_FILE_NAME_LEN];
    memcpy(filePath, TEMP_FILE_NAME, TEMP_FILE_NAME_LEN);

    int fd = mkstemp(filePath);

    if (fd < 0) {
        return -1;
    }

    write(fd, data, size);
    close(fd);

    android::sp<android::KeyCharacterMap> m;
    android::KeyCharacterMap::load(filePath, format, &m);

    remove(filePath);

    return 0;
}