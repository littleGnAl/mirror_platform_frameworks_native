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
    // Notify that the framework was disconnected.
    void (*on_framework_disconnected)(void);
    // Notify that the framework was connected.
    void (*on_framework_connected)(void);
    // Callback for a successful user authorization. |id| is the internal id of
    // the connected device.
    void (*key_authorized)(void* arg, uint64_t id);
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

// Let system_server know that |guid| has been successfully used for authentication.
// The return is the |id| used internally by the library, when using
// |adbd_wifi_notify_disconnect|.
uint64_t adbd_wifi_notify_auth(AdbdWifiContext* ctx, const char* guid, size_t len);

// Let system_server know that a connection has been closed.
void adbd_wifi_notify_disconnect(AdbdWifiContext* ctx, uint64_t id);

enum AdbdWifiFeature {
};

bool adbd_wifi_supports_feature(AdbdWifiFeature f);

}  // extern "C"
