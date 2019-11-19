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

namespace adbwifi {
namespace pairing {

const uint8_t kCurrentKeyHeaderVersion = 1;
const uint8_t kMinSupportedKeyHeaderVersion = 1;
const uint8_t kMaxSupportedKeyHeaderVersion = 1;
const size_t kPeerNameLength = 128;
const size_t kPeerGuidLength = 128;
const uint32_t kMaxPayloadSize = 8192;

struct PairingPacketHeader {
    uint8_t version;       // PairingPacket version
    uint8_t type;          // the type of packet (PairingPacket.Type)
    uint32_t payload;      // Size of the payload in bytes
} __attribute__((packed));

// Payload of the PairingPacket::Type_CERTIFICATE type
struct PeerInfo {
    char name[kPeerNameLength]; // Short name of the peer
    char guid[kPeerGuidLength]; // GUID of the peer
    // Followed by the certificate. Size can be computed by |payload| -
    // sizeof(PeerInfo).
} __attribute__((packed));

}  // namespace pairing
}  // namespace adbwifi
