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

#include <stddef.h>
#include <stdint.h>

const uint8_t kCurrentKeyHeaderVersion = 1;
const uint8_t kMinSupportedKeyHeaderVersion = 1;
const uint8_t kMaxSupportedKeyHeaderVersion = 1;
const size_t kPublicKeyNameLength = 128;
const size_t kPublicKeyIdLength = 128;

struct PublicKeyHeader {
    uint8_t version;
    uint8_t type;
    uint32_t bits;
    uint32_t payload;
    char name[kPublicKeyNameLength];
    char id[kPublicKeyIdLength];
} __attribute__((packed));
