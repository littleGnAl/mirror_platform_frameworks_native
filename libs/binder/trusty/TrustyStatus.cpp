/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include "TrustyStatus.h"
#include "../RpcState.h"

namespace android {

status_t statusFromTrusty(int rc) {
    LOG_RPC_DETAIL("Trusty error: %d", rc);
    switch (rc) {
        case NO_ERROR:
            return OK;
        /* TODO: more errors */
        default:
            return UNKNOWN_ERROR;
    }
}

int statusToTrusty(status_t status) {
    switch (status) {
        case OK:
            return NO_ERROR;
        /* TODO: more errors */
        default:
            return ERR_GENERIC;
    }
}

} // namespace android
