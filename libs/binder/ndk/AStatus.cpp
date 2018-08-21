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

#include <binder/AStatus.h>

#include <binder/Status.h>

using ::android::binder::Status;

struct AStatus {
    const Status* operator->() const { return &mStatus; }
    Status* operator->() { return &mStatus; }

    AStatus(transport_status_t transportStatus, service_status_t serviceStatus) {
        if (transportStatus == EX_SERVICE_SPECIFIC) {
            mStatus = Status::fromServiceSpecificError(serviceStatus);
        } else {
            mStatus = Status::fromExceptionCode(transportStatus);
        }
    }

private:
    Status mStatus;
};

AStatus* AStatus_newOk() {
    return new AStatus(EX_NONE, EX_NONE);
}
AStatus* AStatus_newServiceSpecific(service_status_t status) {
    return new AStatus(EX_SERVICE_SPECIFIC, status);
}
AStatus* AStatus_newTransportSpecific(transport_status_t status) {
    return new AStatus(status, EX_NONE);
}
void AStatus_delete(AStatus* status) {
    delete status;
}
bool AStatus_isOk(AStatus* status) {
    return (*status)->isOk();
}
transport_status_t AStatus_getExceptionCode(AStatus* status) {
    return (*status)->exceptionCode();
}
service_status_t AStatus_getTransactionError(AStatus* status) {
    return (*status)->transactionError();
}
