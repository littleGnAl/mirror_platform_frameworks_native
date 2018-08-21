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

#include <binder/AParcel.h>
#include "AParcel_internal.h"

#include "AIBinder_internal.h"

#include <binder/Parcel.h>

using ::android::IBinder;
using ::android::sp;

AParcel* AParcel_new() {
    return new AParcel;
}

void AParcel_delete(AParcel* parcel) {
    delete parcel;
}

// FIXME: use nullable strong binder?
transport_status_t AParcel_writeStrongBinder(AParcel* parcel, const AIBinder* binder) {
    return (*parcel)->writeStrongBinder(binder->getBinder());
}
transport_status_t AParcel_readStrongBinder(AParcel* parcel, AIBinder** binder) {
    sp<IBinder> remoteBinder = nullptr;
    transport_status_t status = (*parcel)->readStrongBinder(&remoteBinder);
    if (status != EX_NONE) {
        return status;
    }
    *binder = AIBinder::newRemoteBinder(remoteBinder);
    return status;
}

// See gen_parcel_helper.py. These auto-generated read/write methods use the same types for
// libbinder and this library.
// @START
transport_status_t AParcel_writeInt32(AParcel* parcel, int32_t value) {
    return (*parcel)->writeInt32(value);
}
transport_status_t AParcel_writeUint32(AParcel* parcel, uint32_t value) {
    return (*parcel)->writeUint32(value);
}
transport_status_t AParcel_writeInt64(AParcel* parcel, int64_t value) {
    return (*parcel)->writeInt64(value);
}
transport_status_t AParcel_writeUint64(AParcel* parcel, uint64_t value) {
    return (*parcel)->writeUint64(value);
}
transport_status_t AParcel_writeFloat(AParcel* parcel, float value) {
    return (*parcel)->writeFloat(value);
}
transport_status_t AParcel_writeDouble(AParcel* parcel, double value) {
    return (*parcel)->writeDouble(value);
}
transport_status_t AParcel_writeBool(AParcel* parcel, bool value) {
    return (*parcel)->writeBool(value);
}
transport_status_t AParcel_writeChar(AParcel* parcel, char16_t value) {
    return (*parcel)->writeChar(value);
}
transport_status_t AParcel_writeByte(AParcel* parcel, int8_t value) {
    return (*parcel)->writeByte(value);
}
transport_status_t AParcel_readInt32(AParcel* parcel, int32_t* value) {
    return (*parcel)->readInt32(value);
}
transport_status_t AParcel_readUint32(AParcel* parcel, uint32_t* value) {
    return (*parcel)->readUint32(value);
}
transport_status_t AParcel_readInt64(AParcel* parcel, int64_t* value) {
    return (*parcel)->readInt64(value);
}
transport_status_t AParcel_readUint64(AParcel* parcel, uint64_t* value) {
    return (*parcel)->readUint64(value);
}
transport_status_t AParcel_readFloat(AParcel* parcel, float* value) {
    return (*parcel)->readFloat(value);
}
transport_status_t AParcel_readDouble(AParcel* parcel, double* value) {
    return (*parcel)->readDouble(value);
}
transport_status_t AParcel_readBool(AParcel* parcel, bool* value) {
    return (*parcel)->readBool(value);
}
transport_status_t AParcel_readChar(AParcel* parcel, char16_t* value) {
    return (*parcel)->readChar(value);
}
transport_status_t AParcel_readByte(AParcel* parcel, int8_t* value) {
    return (*parcel)->readByte(value);
}
// @END
