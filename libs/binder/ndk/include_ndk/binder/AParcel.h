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

#pragma once

#include <sys/cdefs.h>

#include <binder/AStatus.h>

struct AIBinder;
typedef struct AIBinder AIBinder;

__BEGIN_DECLS

struct AParcel;
typedef struct AParcel AParcel;

AParcel* AParcel_new();
void AParcel_delete(AParcel* parcel);

transport_status_t AParcel_writeStrongBinder(AParcel* parcel, const AIBinder* binder);
transport_status_t AParcel_readStrongBinder(AParcel* parcel, AIBinder** binder);

// See gen_parcel_helper.py. These auto-generated read/write methods use the same types for
// libbinder and this library.
// @START
transport_status_t AParcel_writeInt32(AParcel* parcel, int32_t value);
transport_status_t AParcel_writeUint32(AParcel* parcel, uint32_t value);
transport_status_t AParcel_writeInt64(AParcel* parcel, int64_t value);
transport_status_t AParcel_writeUint64(AParcel* parcel, uint64_t value);
transport_status_t AParcel_writeFloat(AParcel* parcel, float value);
transport_status_t AParcel_writeDouble(AParcel* parcel, double value);
transport_status_t AParcel_writeBool(AParcel* parcel, bool value);
transport_status_t AParcel_writeChar(AParcel* parcel, char16_t value);
transport_status_t AParcel_writeByte(AParcel* parcel, int8_t value);
transport_status_t AParcel_readInt32(AParcel* parcel, int32_t* value);
transport_status_t AParcel_readUint32(AParcel* parcel, uint32_t* value);
transport_status_t AParcel_readInt64(AParcel* parcel, int64_t* value);
transport_status_t AParcel_readUint64(AParcel* parcel, uint64_t* value);
transport_status_t AParcel_readFloat(AParcel* parcel, float* value);
transport_status_t AParcel_readDouble(AParcel* parcel, double* value);
transport_status_t AParcel_readBool(AParcel* parcel, bool* value);
transport_status_t AParcel_readChar(AParcel* parcel, char16_t* value);
transport_status_t AParcel_readByte(AParcel* parcel, int8_t* value);
// @END

__END_DECLS
