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

binder_status_t AParcel_writeStrongBinder(AParcel* parcel, AIBinder* binder);
binder_status_t AParcel_readStrongBinder(const AParcel* parcel, AIBinder** binder);
binder_status_t AParcel_readNullableStrongBinder(const AParcel* parcel, AIBinder** binder);

// See gen_parcel_helper.py. These auto-generated read/write methods use the same types for
// libbinder and this library.
// @START
/*
 * Writes int32_t value to the end of a non-null parcel.
 */
binder_status_t AParcel_writeInt32(AParcel* parcel, int32_t value);

/*
 * Writes uint32_t value to the end of a non-null parcel.
 */
binder_status_t AParcel_writeUint32(AParcel* parcel, uint32_t value);

/*
 * Writes int64_t value to the end of a non-null parcel.
 */
binder_status_t AParcel_writeInt64(AParcel* parcel, int64_t value);

/*
 * Writes uint64_t value to the end of a non-null parcel.
 */
binder_status_t AParcel_writeUint64(AParcel* parcel, uint64_t value);

/*
 * Writes float value to the end of a non-null parcel.
 */
binder_status_t AParcel_writeFloat(AParcel* parcel, float value);

/*
 * Writes double value to the end of a non-null parcel.
 */
binder_status_t AParcel_writeDouble(AParcel* parcel, double value);

/*
 * Writes bool value to the end of a non-null parcel.
 */
binder_status_t AParcel_writeBool(AParcel* parcel, bool value);

/*
 * Writes char16_t value to the end of a non-null parcel.
 */
binder_status_t AParcel_writeChar(AParcel* parcel, char16_t value);

/*
 * Writes int8_t value to the end of a non-null parcel.
 */
binder_status_t AParcel_writeByte(AParcel* parcel, int8_t value);

/*
 * Reads into int32_t value from the next location in a non-null parcel.
 */
binder_status_t AParcel_readInt32(const AParcel* parcel, int32_t* value);

/*
 * Reads into uint32_t value from the next location in a non-null parcel.
 */
binder_status_t AParcel_readUint32(const AParcel* parcel, uint32_t* value);

/*
 * Reads into int64_t value from the next location in a non-null parcel.
 */
binder_status_t AParcel_readInt64(const AParcel* parcel, int64_t* value);

/*
 * Reads into uint64_t value from the next location in a non-null parcel.
 */
binder_status_t AParcel_readUint64(const AParcel* parcel, uint64_t* value);

/*
 * Reads into float value from the next location in a non-null parcel.
 */
binder_status_t AParcel_readFloat(const AParcel* parcel, float* value);

/*
 * Reads into double value from the next location in a non-null parcel.
 */
binder_status_t AParcel_readDouble(const AParcel* parcel, double* value);

/*
 * Reads into bool value from the next location in a non-null parcel.
 */
binder_status_t AParcel_readBool(const AParcel* parcel, bool* value);

/*
 * Reads into char16_t value from the next location in a non-null parcel.
 */
binder_status_t AParcel_readChar(const AParcel* parcel, char16_t* value);

/*
 * Reads into int8_t value from the next location in a non-null parcel.
 */
binder_status_t AParcel_readByte(const AParcel* parcel, int8_t* value);

// @END

__END_DECLS
