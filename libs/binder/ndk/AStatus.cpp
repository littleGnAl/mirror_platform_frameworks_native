/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <android/binder_status.h>
#include "AStatus_internal.h"

using ::android::binder::Status;

AStatus* AStatus_newOk() {
    return new AStatus();
}
AStatus* AStatus_fromServiceSpecificError(binder_status_t ex) {
    return new AStatus(Status::fromServiceSpecificError(ex));
}
AStatus* AStatus_fromServiceSpecificErrorWithMessage(binder_status_t ex, const char* message) {
    return new AStatus(Status::fromServiceSpecificError(ex, message));
}
void AStatus_delete(AStatus* status) {
    delete status;
}
