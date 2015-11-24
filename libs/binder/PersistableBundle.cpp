/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <binder/PersistableBundle.h>

#include <binder/IBinder.h>
#include <binder/Parcel.h>
#include <log/log.h>
#include <utils/Errors.h>
#include <utils/String16.h>

using android::BAD_TYPE;
using android::BAD_VALUE;
using android::NAME_NOT_FOUND;
using android::NO_ERROR;
using android::Parcel;
using android::sp;
using android::status_t;
using android::UNKNOWN_ERROR;

namespace {
// Keep in sync with BUNDLE_MAGIC in
// frameworks/base/core/java/android/os/BasePersistableBundle.java.
const int32_t kPersistableBundleMagic = 0x4C444E42;

// This is a subset of the VAL_* constants in Parcel.java.
// Keep in sync with frameworks/base/core/java/android/os/Parcel.java.
const int kValString = 0;
const int kValInteger = 1;
const int kValLong = 6;
const int kValDouble = 8;
const int kValBoolean = 9;
const int kValStringArray = 14;
const int kValIntArray = 18;
const int kValLongArray = 19;
const int kValBooleanArray = 23;
const int kValPersistableBundle = 25;
const int kValDoubleArray = 28;
}  // namespace

namespace android {

namespace os {

// Read and write macros that return the error status if the read or write
// operation fails.
#define writeBoolAndReturnIfFailed(parcel, value) \
  {                                               \
    status_t status = parcel->writeBool(value);   \
    if (status) return status;                    \
  }

#define writeInt32AndReturnIfFailed(parcel, value) \
  {                                                \
    status_t status = parcel->writeInt32(value);   \
    if (status) return status;                     \
  }

#define writeInt64AndReturnIfFailed(parcel, value) \
  {                                                \
    status_t status = parcel->writeInt64(value);   \
    if (status) return status;                     \
  }

#define writeDoubleAndReturnIfFailed(parcel, value) \
  {                                                 \
    status_t status = parcel->writeDouble(value);   \
    if (status) return status;                      \
  }

#define writeString16AndReturnIfFailed(parcel, value) \
  {                                                   \
    status_t status = parcel->writeString16(value);   \
    if (status) return status;                        \
  }

#define writeBoolVectorAndReturnIfFailed(parcel, value) \
  {                                                     \
    status_t status = parcel->writeBoolVector(value);   \
    if (status) return status;                          \
  }

#define writeInt32VectorAndReturnIfFailed(parcel, value) \
  {                                                      \
    status_t status = parcel->writeInt32Vector(value);   \
    if (status) return status;                           \
  }

#define writeInt64VectorAndReturnIfFailed(parcel, value) \
  {                                                      \
    status_t status = parcel->writeInt64Vector(value);   \
    if (status) return status;                           \
  }

#define writeDoubleVectorAndReturnIfFailed(parcel, value) \
  {                                                       \
    status_t status = parcel->writeDoubleVector(value);   \
    if (status) return status;                            \
  }

#define writeString16VectorAndReturnIfFailed(parcel, value) \
  {                                                         \
    status_t status = parcel->writeString16Vector(value);   \
    if (status) return status;                              \
  }

#define writeParcelableAndReturnIfFailed(parcel, value) \
  {                                                     \
    status_t status = parcel->writeParcelable(value);   \
    if (status) return status;                          \
  }

#define readBoolAndReturnIfFailed(parcel, out) \
  {                                            \
    status_t status = parcel->readBool(out);   \
    if (status) return status;                 \
  }

#define readInt32AndReturnIfFailed(parcel, out) \
  {                                             \
    status_t status = parcel->readInt32(out);   \
    if (status) return status;                  \
  }

#define readInt64AndReturnIfFailed(parcel, out) \
  {                                             \
    status_t status = parcel->readInt64(out);   \
    if (status) return status;                  \
  }

#define readDoubleAndReturnIfFailed(parcel, out) \
  {                                              \
    status_t status = parcel->readDouble(out);   \
    if (status) return status;                   \
  }

#define readString16AndReturnIfFailed(parcel, out) \
  {                                                \
    status_t status = parcel->readString16(out);   \
    if (status) return status;                     \
  }

#define readBoolVectorAndReturnIfFailed(parcel, out) \
  {                                                  \
    status_t status = parcel->readBoolVector(out);   \
    if (status) return status;                       \
  }

#define readInt32VectorAndReturnIfFailed(parcel, out) \
  {                                                   \
    status_t status = parcel->readInt32Vector(out);   \
    if (status) return status;                        \
  }

#define readInt64VectorAndReturnIfFailed(parcel, out) \
  {                                                   \
    status_t status = parcel->readInt64Vector(out);   \
    if (status) return status;                        \
  }

#define readDoubleVectorAndReturnIfFailed(parcel, out) \
  {                                                    \
    status_t status = parcel->readDoubleVector(out);   \
    if (status) return status;                         \
  }

#define readString16VectorAndReturnIfFailed(parcel, out) \
  {                                                      \
    status_t status = parcel->readString16Vector(out);   \
    if (status) return status;                           \
  }

#define readParcelableAndReturnIfFailed(parcel, out) \
  {                                                  \
    status_t status = parcel->readParcelable(out);   \
    if (status) return status;                       \
  }

status_t PersistableBundle::writeToParcel(Parcel* parcel) const {
  // Keep implementation in sync with writeToParcelInner() in
  // frameworks/base/core/java/android/os/BaseBundle.java.

  // Special case for empty bundles.
  if (bool_map_.empty() &&
      int_map_.empty() &&
      long_map_.empty() &&
      double_map_.empty() &&
      string_map_.empty() &&
      bool_vector_map_.empty() &&
      int_vector_map_.empty() &&
      long_vector_map_.empty() &&
      double_vector_map_.empty() &&
      string_vector_map_.empty() &&
      persistable_bundle_map_.empty()) {
    writeInt32AndReturnIfFailed(parcel, 0);
    return NO_ERROR;
  }

  size_t length_pos = parcel->dataPosition();
  writeInt32AndReturnIfFailed(parcel, 1);  // dummy, will hold length
  writeInt32AndReturnIfFailed(parcel, kPersistableBundleMagic);

  size_t start_pos = parcel->dataPosition();
  writeToParcelInner(parcel);
  size_t end_pos = parcel->dataPosition();

  // Backpatch length.
  parcel->setDataPosition(length_pos);
  size_t length = end_pos - start_pos;
  if (static_cast<int32_t>(length) < 0) {
    ALOGE("Parcel length (%u) too large to store in 32-bit signed int", length);
    return BAD_VALUE;
  }
  writeInt32AndReturnIfFailed(parcel, static_cast<int32_t>(length));
  parcel->setDataPosition(end_pos);
  return NO_ERROR;
}

status_t PersistableBundle::readFromParcel(const Parcel* parcel) {
  // Keep implementation in sync with readFromParcelInner() in
  // frameworks/base/core/java/android/os/BasePersistableBundle.java.
  int32_t length = parcel->readInt32();
  if (length < 0) {
    ALOGE("Bad length in parcel: %d", length);
    return BAD_VALUE;
  }

  readFromParcelInner(parcel, static_cast<size_t>(length));
  return NO_ERROR;
}

void PersistableBundle::putBoolean(const String16& key, bool value) {
  bool_map_.emplace(key, value);
}

void PersistableBundle::putInt(const String16& key, int32_t value) {
  int_map_.emplace(key, value);
}

void PersistableBundle::putLong(const String16& key, int64_t value) {
  long_map_.emplace(key, value);
}

void PersistableBundle::putDouble(const String16& key, double value) {
  double_map_.emplace(key, value);
}

void PersistableBundle::putString(const String16& key, const String16& value) {
  string_map_.emplace(key, value);
}

void PersistableBundle::putBooleanVector(const String16& key,
                                         const std::vector<bool>& value) {
  bool_vector_map_.emplace(key, value);
}

void PersistableBundle::putIntVector(const String16& key,
                                     const std::vector<int32_t>& value) {
  int_vector_map_.emplace(key, value);
}

void PersistableBundle::putLongVector(const String16& key,
                                      const std::vector<int64_t>& value) {
  long_vector_map_.emplace(key, value);
}

void PersistableBundle::putDoubleVector(const String16& key,
                                        const std::vector<double>& value) {
  double_vector_map_.emplace(key, value);
}

void PersistableBundle::putStringVector(const String16& key,
                                        const std::vector<String16>& value) {
  string_vector_map_.emplace(key, value);
}

void PersistableBundle::putPersistableBundle(const String16& key,
                                             const PersistableBundle& value) {
  persistable_bundle_map_.emplace(key, value);
}

status_t PersistableBundle::getBoolean(const String16& key, bool* out) {
  const auto& it = bool_map_.find(key);
  if (it == bool_map_.end()) return NAME_NOT_FOUND;
  *out = it->second;
  return NO_ERROR;
}

status_t PersistableBundle::getInt(const String16& key, int32_t* out) {
  const auto& it = int_map_.find(key);
  if (it == int_map_.end()) return NAME_NOT_FOUND;
  *out = it->second;
  return NO_ERROR;
}

status_t PersistableBundle::getLong(const String16& key, int64_t* out) {
  const auto& it = long_map_.find(key);
  if (it == long_map_.end()) return NAME_NOT_FOUND;
  *out = it->second;
  return NO_ERROR;
}

status_t PersistableBundle::getDouble(const String16& key, double* out) {
  const auto& it = double_map_.find(key);
  if (it == double_map_.end()) return NAME_NOT_FOUND;
  *out = it->second;
  return NO_ERROR;
}

status_t PersistableBundle::getString(const String16& key, String16* out) {
  const auto& it = string_map_.find(key);
  if (it == string_map_.end()) return NAME_NOT_FOUND;
  *out = it->second;
  return NO_ERROR;
}

status_t PersistableBundle::getBooleanVector(const String16& key,
                                             std::vector<bool>* out) {
  const auto& it = bool_vector_map_.find(key);
  if (it == bool_vector_map_.end()) return NAME_NOT_FOUND;
  *out = it->second;
  return NO_ERROR;
}

status_t PersistableBundle::getIntVector(const String16& key,
                                         std::vector<int32_t>* out) {
  const auto& it = int_vector_map_.find(key);
  if (it == int_vector_map_.end()) return NAME_NOT_FOUND;
  *out = it->second;
  return NO_ERROR;
}

status_t PersistableBundle::getLongVector(const String16& key,
                                          std::vector<int64_t>* out) {
  const auto& it = long_vector_map_.find(key);
  if (it == long_vector_map_.end()) return NAME_NOT_FOUND;
  *out = it->second;
  return NO_ERROR;
}

status_t PersistableBundle::getDoubleVector(const String16& key,
                                            std::vector<double>* out) {
  const auto& it = double_vector_map_.find(key);
  if (it == double_vector_map_.end()) return NAME_NOT_FOUND;
  *out = it->second;
  return NO_ERROR;
}

status_t PersistableBundle::getStringVector(const String16& key,
                                            std::vector<String16>* out) {
  const auto& it = string_vector_map_.find(key);
  if (it == string_vector_map_.end()) return NAME_NOT_FOUND;
  *out = it->second;
  return NO_ERROR;
}

status_t PersistableBundle::getPersistableBundle(const String16& key,
                                                 PersistableBundle* out) {
  const auto& it = persistable_bundle_map_.find(key);
  if (it == persistable_bundle_map_.end()) return NAME_NOT_FOUND;
  *out = it->second;
  return NO_ERROR;
}

status_t PersistableBundle::writeToParcelInner(Parcel* parcel) const {
  for (const auto& key_val_pair : bool_map_) {
    writeString16AndReturnIfFailed(parcel, key_val_pair.first);
    writeInt32AndReturnIfFailed(parcel, kValBoolean);
    writeBoolAndReturnIfFailed(parcel, key_val_pair.second);
  }
  for (const auto& key_val_pair : int_map_) {
    writeString16AndReturnIfFailed(parcel, key_val_pair.first);
    writeInt32AndReturnIfFailed(parcel, kValInteger);
    writeInt32AndReturnIfFailed(parcel, key_val_pair.second);
  }
  for (const auto& key_val_pair : long_map_) {
    writeString16AndReturnIfFailed(parcel, key_val_pair.first);
    writeInt32AndReturnIfFailed(parcel, kValLong);
    writeInt64AndReturnIfFailed(parcel, key_val_pair.second);
  }
  for (const auto& key_val_pair : double_map_) {
    writeString16AndReturnIfFailed(parcel, key_val_pair.first);
    writeInt32AndReturnIfFailed(parcel, kValDouble);
    writeDoubleAndReturnIfFailed(parcel, key_val_pair.second);
  }
  for (const auto& key_val_pair : string_map_) {
    writeString16AndReturnIfFailed(parcel, key_val_pair.first);
    writeInt32AndReturnIfFailed(parcel, kValString);
    writeString16AndReturnIfFailed(parcel, key_val_pair.second);
  }
  for (const auto& key_val_pair : bool_vector_map_) {
    writeString16AndReturnIfFailed(parcel, key_val_pair.first);
    writeInt32AndReturnIfFailed(parcel, kValBooleanArray);
    writeBoolVectorAndReturnIfFailed(parcel, key_val_pair.second);
  }
  for (const auto& key_val_pair : int_vector_map_) {
    writeString16AndReturnIfFailed(parcel, key_val_pair.first);
    writeInt32AndReturnIfFailed(parcel, kValIntArray);
    writeInt32VectorAndReturnIfFailed(parcel, key_val_pair.second);
  }
  for (const auto& key_val_pair : long_vector_map_) {
    writeString16AndReturnIfFailed(parcel, key_val_pair.first);
    writeInt32AndReturnIfFailed(parcel, kValLongArray);
    writeInt64VectorAndReturnIfFailed(parcel, key_val_pair.second);
  }
  for (const auto& key_val_pair : double_vector_map_) {
    writeString16AndReturnIfFailed(parcel, key_val_pair.first);
    writeInt32AndReturnIfFailed(parcel, kValDoubleArray);
    writeDoubleVectorAndReturnIfFailed(parcel, key_val_pair.second);
  }
  for (const auto& key_val_pair : string_vector_map_) {
    writeString16AndReturnIfFailed(parcel, key_val_pair.first);
    writeInt32AndReturnIfFailed(parcel, kValStringArray);
    writeString16VectorAndReturnIfFailed(parcel, key_val_pair.second);
  }
  for (const auto& key_val_pair : persistable_bundle_map_) {
    writeString16AndReturnIfFailed(parcel, key_val_pair.first);
    writeInt32AndReturnIfFailed(parcel, kValPersistableBundle);
    writeParcelableAndReturnIfFailed(parcel, key_val_pair.second);
  }
  return NO_ERROR;
}

status_t PersistableBundle::readFromParcelInner(const Parcel* parcel,
                                                size_t length) {
  if (length == 0) {
    // Empty PersistableBundle or end of data.
    return NO_ERROR;
  }

  int32_t magic;
  readInt32AndReturnIfFailed(parcel, &magic);
  if (magic != kPersistableBundleMagic) {
    ALOGE("Bad magic number for PersistableBundle: 0x%08x", magic);
    return BAD_VALUE;
  }

  while (parcel->dataAvail() > 0) {
    // Note: if there is any trailing data at the end of the Parcel that does
    // not form a valid key-value pair, we will terminate this function with an
    // error.
    String16 key;
    int32_t value_type;
    readString16AndReturnIfFailed(parcel, &key);
    readInt32AndReturnIfFailed(parcel, &value_type);

    switch (value_type) {
      case kValString: {
        String16 value;
        readString16AndReturnIfFailed(parcel, &value);
        if (!string_map_.emplace(key, value).second) return UNKNOWN_ERROR;
        break;
      }
      case kValInteger: {
        int32_t value;
        readInt32AndReturnIfFailed(parcel, &value);
        if (!int_map_.emplace(key, value).second) return UNKNOWN_ERROR;
        break;
      }
      case kValLong: {
        int64_t value;
        readInt64AndReturnIfFailed(parcel, &value);
        if (!long_map_.emplace(key, value).second) return UNKNOWN_ERROR;
        break;
      }
      case kValDouble: {
        double value;
        readDoubleAndReturnIfFailed(parcel, &value);
        if (!double_map_.emplace(key, value).second) return UNKNOWN_ERROR;
        break;
      }
      case kValBoolean: {
        bool value;
        readBoolAndReturnIfFailed(parcel, &value);
        if (!bool_map_.emplace(key, value).second) return UNKNOWN_ERROR;
        break;
      }
      case kValStringArray: {
        std::vector<String16> value;
        readString16VectorAndReturnIfFailed(parcel, &value);
        if (!string_vector_map_.emplace(key, value).second)
          return UNKNOWN_ERROR;
        break;
      }
      case kValIntArray: {
        std::vector<int32_t> value;
        readInt32VectorAndReturnIfFailed(parcel, &value);
        if (!int_vector_map_.emplace(key, value).second) return UNKNOWN_ERROR;
        break;
      }
      case kValLongArray: {
        std::vector<int64_t> value;
        readInt64VectorAndReturnIfFailed(parcel, &value);
        if (!long_vector_map_.emplace(key, value).second) return UNKNOWN_ERROR;
        break;
      }
      case kValBooleanArray: {
        std::vector<bool> value;
        readBoolVectorAndReturnIfFailed(parcel, &value);
        if (!bool_vector_map_.emplace(key, value).second) return UNKNOWN_ERROR;
        break;
      }
      case kValPersistableBundle: {
        PersistableBundle value;
        readParcelableAndReturnIfFailed(parcel, &value);
        if (!persistable_bundle_map_.emplace(key, value).second)
          return UNKNOWN_ERROR;
        break;
      }
      case kValDoubleArray: {
        std::vector<double> value;
        readDoubleVectorAndReturnIfFailed(parcel, &value);
        if (!double_vector_map_.emplace(key, value).second)
          return UNKNOWN_ERROR;
        break;
      }
      default: {
        ALOGE("Unrecognized type: %d", value_type);
        return BAD_TYPE;
        break;
      }
    }
  }

  return NO_ERROR;
}

}  // namespace os

}  // namespace android
