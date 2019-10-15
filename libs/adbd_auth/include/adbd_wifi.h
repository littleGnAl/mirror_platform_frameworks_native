#pragma once

/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <stdbool.h>
#include <stdint.h>
#include <sys/types.h>

extern "C" {

struct AdbdWifiCallbacksV1 {
    // Turns on/off device discovery. When on, devices will be able to attempt
    // to pair with this device. Returns true if discovery was enabled/disabled
    // successfully.
    bool (*set_discovery_enabled)(bool enable);
    void (*device_pairing_complete)(uint64_t id, bool is_paired);
};

struct AdbdWifiCallbacks {
    uint32_t version;
    union {
        AdbdWifiCallbacksV1 v1;
    } callbacks;
};

struct AdbdWifiContext;

AdbdWifiContext* adbd_wifi_new(AdbdWifiCallbacks* callbacks);
void adbd_wifi_delete(AdbdWifiContext* ctx);
void adbd_wifi_run(AdbdWifiContext* ctx);

// Iterate through the list of authorized public keys.
// Return false from the callback to stop iteration.
void adbd_wifi_get_public_keys(AdbdWifiContext* ctx,
                               bool (*callback)(const char* public_key, size_t len, void* arg),
                               void* arg);

// Let system_server know that a key has been successfully used for authentication.
uint64_t adbd_wifi_notify_auth(AdbdWifiContext* ctx, const char* public_key, size_t len);

// Let system_server know that a connection has been closed.
void adbd_wifi_notify_disconnect(AdbdWifiContext* ctx, uint64_t id);

// Let system_server know a pairing device provided a pairing code.
// Returns true if the pairing code was correct, false otherwise.
// TODO: pass device_id to this function?
bool adbd_wifi_pairing_code(AdbdWifiContext* ctx,
                            const char* public_key,
                            const uint8_t* encrypted_code,
                            uint64_t size_bytes);

enum AdbdWifiFeature {
};

bool adbd_wifi_supports_feature(AdbdWifiFeature f);

}  // extern "C"
