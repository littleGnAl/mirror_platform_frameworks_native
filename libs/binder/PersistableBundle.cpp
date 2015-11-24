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

#include <limits>

#include <binder/IBinder.h>
#include <binder/Parcel.h>
#include <log/log.h>
#include <utils/Errors.h>

using android::BAD_TYPE;
using android::BAD_VALUE;
using android::NO_ERROR;
using android::Parcel;
using android::sp;
using android::status_t;

enum {
  /*
   * Keep in sync with BUNDLE_MAGIC in
   * frameworks/base/core/java/android/os/BasePersistableBundle.java.
   */
  BUNDLE_MAGIC = 0x4C444E42,
};

enum {
  // Keep in sync with frameworks/base/core/java/android/os/Parcel.java.
  VAL_STRING = 0,
  VAL_INTEGER = 1,
  VAL_LONG = 6,
  VAL_DOUBLE = 8,
  VAL_BOOLEAN = 9,
  VAL_STRINGARRAY = 14,
  VAL_INTARRAY = 18,
  VAL_LONGARRAY = 19,
  VAL_BOOLEANARRAY = 23,
  VAL_PERSISTABLEBUNDLE = 25,
  VAL_DOUBLEARRAY = 28,
};

namespace android {

namespace os {

#define RETURN_IF_FAILED(status) \
  {                              \
    if (status) return status;   \
  }

status_t PersistableBundle::writeToParcel(Parcel* parcel) const {
  /*
   * Keep implementation in sync with writeToParcelInner() in
   * frameworks/base/core/java/android/os/BaseBundle.java.
   */

  // Special case for empty bundles.
  if (empty()) {
    RETURN_IF_FAILED(parcel->writeInt32(0));
    return NO_ERROR;
  }

  size_t length_pos = parcel->dataPosition();
  RETURN_IF_FAILED(parcel->writeInt32(1));  // dummy, will hold length
  RETURN_IF_FAILED(parcel->writeInt32(BUNDLE_MAGIC));

  size_t start_pos = parcel->dataPosition();
  writeToParcelInner(parcel);
  size_t end_pos = parcel->dataPosition();

  // Backpatch length. This length value includes the length header.
  parcel->setDataPosition(length_pos);
  size_t length = end_pos - start_pos;
  if (length > std::numeric_limits<int32_t>::max()) {
    ALOGE("Parcel length (%u) too large to store in 32-bit signed int", length);
    return BAD_VALUE;
  }
  RETURN_IF_FAILED(parcel->writeInt32(static_cast<int32_t>(length)));
  parcel->setDataPosition(end_pos);
  return NO_ERROR;
}

status_t PersistableBundle::readFromParcel(const Parcel* parcel) {
  /*
   * Keep implementation in sync with readFromParcelInner() in
   * frameworks/base/core/java/android/os/BasePersistableBundle.java.
   */
  int32_t length = parcel->readInt32();
  if (length < 0) {
    ALOGE("Bad length in parcel: %d", length);
    return BAD_VALUE;
  }

  readFromParcelInner(parcel, static_cast<size_t>(length));
  return NO_ERROR;
}

bool PersistableBundle::empty() const {
    return (mBoolMap.empty() &&
            mIntMap.empty() &&
            mLongMap.empty() &&
            mDoubleMap.empty() &&
            mStringMap.empty() &&
            mBoolVectorMap.empty() &&
            mIntVectorMap.empty() &&
            mLongVectorMap.empty() &&
            mDoubleVectorMap.empty() &&
            mStringVectorMap.empty() &&
            mPersistableBundleMap.empty());
}

size_t PersistableBundle::size() const {
  return (mBoolMap.size() +
          mIntMap.size() +
          mLongMap.size() +
          mDoubleMap.size() +
          mStringMap.size() +
          mBoolVectorMap.size() +
          mIntVectorMap.size() +
          mLongVectorMap.size() +
          mDoubleVectorMap.size() +
          mStringVectorMap.size() +
          mPersistableBundleMap.size());
}

void PersistableBundle::putBoolean(const String16& key, bool value) {
  mBoolMap.emplace(key, value);
}

void PersistableBundle::putInt(const String16& key, int32_t value) {
  mIntMap.emplace(key, value);
}

void PersistableBundle::putLong(const String16& key, int64_t value) {
  mLongMap.emplace(key, value);
}

void PersistableBundle::putDouble(const String16& key, double value) {
  mDoubleMap.emplace(key, value);
}

void PersistableBundle::putString(const String16& key, const String16& value) {
  mStringMap.emplace(key, value);
}

void PersistableBundle::putBooleanVector(const String16& key,
                                         const std::vector<bool>& value) {
  mBoolVectorMap.emplace(key, value);
}

void PersistableBundle::putIntVector(const String16& key,
                                     const std::vector<int32_t>& value) {
  mIntVectorMap.emplace(key, value);
}

void PersistableBundle::putLongVector(const String16& key,
                                      const std::vector<int64_t>& value) {
  mLongVectorMap.emplace(key, value);
}

void PersistableBundle::putDoubleVector(const String16& key,
                                        const std::vector<double>& value) {
  mDoubleVectorMap.emplace(key, value);
}

void PersistableBundle::putStringVector(const String16& key,
                                        const std::vector<String16>& value) {
  mStringVectorMap.emplace(key, value);
}

void PersistableBundle::putPersistableBundle(const String16& key,
                                             const PersistableBundle& value) {
  mPersistableBundleMap.emplace(key, value);
}

bool PersistableBundle::getBoolean(const String16& key, bool* out) const {
  const auto& it = mBoolMap.find(key);
  if (it == mBoolMap.end()) return false;
  *out = it->second;
  return true;
}

bool PersistableBundle::getInt(const String16& key, int32_t* out) const {
  const auto& it = mIntMap.find(key);
  if (it == mIntMap.end()) return false;
  *out = it->second;
  return true;
}

bool PersistableBundle::getLong(const String16& key, int64_t* out) const {
  const auto& it = mLongMap.find(key);
  if (it == mLongMap.end()) return false;
  *out = it->second;
  return true;
}

bool PersistableBundle::getDouble(const String16& key, double* out) const {
  const auto& it = mDoubleMap.find(key);
  if (it == mDoubleMap.end()) return false;
  *out = it->second;
  return true;
}

bool PersistableBundle::getString(const String16& key, String16* out) const {
  const auto& it = mStringMap.find(key);
  if (it == mStringMap.end()) return false;
  *out = it->second;
  return true;
}

bool PersistableBundle::getBooleanVector(const String16& key,
                                         std::vector<bool>* out) const {
  const auto& it = mBoolVectorMap.find(key);
  if (it == mBoolVectorMap.end()) return false;
  *out = it->second;
  return true;
}

bool PersistableBundle::getIntVector(const String16& key,
                                     std::vector<int32_t>* out) const {
  const auto& it = mIntVectorMap.find(key);
  if (it == mIntVectorMap.end()) return false;
  *out = it->second;
  return true;
}

bool PersistableBundle::getLongVector(const String16& key,
                                      std::vector<int64_t>* out) const {
  const auto& it = mLongVectorMap.find(key);
  if (it == mLongVectorMap.end()) return false;
  *out = it->second;
  return true;
}

bool PersistableBundle::getDoubleVector(const String16& key,
                                        std::vector<double>* out) const {
  const auto& it = mDoubleVectorMap.find(key);
  if (it == mDoubleVectorMap.end()) return false;
  *out = it->second;
  return true;
}

bool PersistableBundle::getStringVector(const String16& key,
                                        std::vector<String16>* out) const {
  const auto& it = mStringVectorMap.find(key);
  if (it == mStringVectorMap.end()) return false;
  *out = it->second;
  return true;
}

bool PersistableBundle::getPersistableBundle(const String16& key,
                                             PersistableBundle* out) const {
  const auto& it = mPersistableBundleMap.find(key);
  if (it == mPersistableBundleMap.end()) return false;
  *out = it->second;
  return true;
}

status_t PersistableBundle::writeToParcelInner(Parcel* parcel) const {
  for (const auto& key_val_pair : mBoolMap) {
    RETURN_IF_FAILED(parcel->writeString16(key_val_pair.first));
    RETURN_IF_FAILED(parcel->writeInt32(VAL_BOOLEAN));
    RETURN_IF_FAILED(parcel->writeBool(key_val_pair.second));
  }
  for (const auto& key_val_pair : mIntMap) {
    RETURN_IF_FAILED(parcel->writeString16(key_val_pair.first));
    RETURN_IF_FAILED(parcel->writeInt32(VAL_INTEGER));
    RETURN_IF_FAILED(parcel->writeInt32(key_val_pair.second));
  }
  for (const auto& key_val_pair : mLongMap) {
    RETURN_IF_FAILED(parcel->writeString16(key_val_pair.first));
    RETURN_IF_FAILED(parcel->writeInt32(VAL_LONG));
    RETURN_IF_FAILED(parcel->writeInt64(key_val_pair.second));
  }
  for (const auto& key_val_pair : mDoubleMap) {
    RETURN_IF_FAILED(parcel->writeString16(key_val_pair.first));
    RETURN_IF_FAILED(parcel->writeInt32(VAL_DOUBLE));
    RETURN_IF_FAILED(parcel->writeDouble(key_val_pair.second));
  }
  for (const auto& key_val_pair : mStringMap) {
    RETURN_IF_FAILED(parcel->writeString16(key_val_pair.first));
    RETURN_IF_FAILED(parcel->writeInt32(VAL_STRING));
    RETURN_IF_FAILED(parcel->writeString16(key_val_pair.second));
  }
  for (const auto& key_val_pair : mBoolVectorMap) {
    RETURN_IF_FAILED(parcel->writeString16(key_val_pair.first));
    RETURN_IF_FAILED(parcel->writeInt32(VAL_BOOLEANARRAY));
    RETURN_IF_FAILED(parcel->writeBoolVector(key_val_pair.second));
  }
  for (const auto& key_val_pair : mIntVectorMap) {
    RETURN_IF_FAILED(parcel->writeString16(key_val_pair.first));
    RETURN_IF_FAILED(parcel->writeInt32(VAL_INTARRAY));
    RETURN_IF_FAILED(parcel->writeInt32Vector(key_val_pair.second));
  }
  for (const auto& key_val_pair : mLongVectorMap) {
    RETURN_IF_FAILED(parcel->writeString16(key_val_pair.first));
    RETURN_IF_FAILED(parcel->writeInt32(VAL_LONGARRAY));
    RETURN_IF_FAILED(parcel->writeInt64Vector(key_val_pair.second));
  }
  for (const auto& key_val_pair : mDoubleVectorMap) {
    RETURN_IF_FAILED(parcel->writeString16(key_val_pair.first));
    RETURN_IF_FAILED(parcel->writeInt32(VAL_DOUBLEARRAY));
    RETURN_IF_FAILED(parcel->writeDoubleVector(key_val_pair.second));
  }
  for (const auto& key_val_pair : mStringVectorMap) {
    RETURN_IF_FAILED(parcel->writeString16(key_val_pair.first));
    RETURN_IF_FAILED(parcel->writeInt32(VAL_STRINGARRAY));
    RETURN_IF_FAILED(parcel->writeString16Vector(key_val_pair.second));
  }
  for (const auto& key_val_pair : mPersistableBundleMap) {
    RETURN_IF_FAILED(parcel->writeString16(key_val_pair.first));
    RETURN_IF_FAILED(parcel->writeInt32(VAL_PERSISTABLEBUNDLE));
    RETURN_IF_FAILED(parcel->writeParcelable(key_val_pair.second));
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
  RETURN_IF_FAILED(parcel->readInt32(&magic));
  if (magic != BUNDLE_MAGIC) {
    ALOGE("Bad magic number for PersistableBundle: 0x%08x", magic);
    return BAD_VALUE;
  }

  while (parcel->dataAvail() > 0) {
    /*
     * Note: if there is any trailing data at the end of the Parcel that does
     * not form a valid key-value pair, we will terminate this function with an
     * error.
     */
    String16 key;
    int32_t value_type;
    RETURN_IF_FAILED(parcel->readString16(&key));
    RETURN_IF_FAILED(parcel->readInt32(&value_type));

    switch (value_type) {
      case VAL_STRING: {
        String16 value;
        RETURN_IF_FAILED(parcel->readString16(&value));
        if (!mStringMap.emplace(key, value).second) return BAD_INDEX;
        break;
      }
      case VAL_INTEGER: {
        int32_t value;
        RETURN_IF_FAILED(parcel->readInt32(&value));
        if (!mIntMap.emplace(key, value).second) return BAD_INDEX;
        break;
      }
      case VAL_LONG: {
        int64_t value;
        RETURN_IF_FAILED(parcel->readInt64(&value));
        if (!mLongMap.emplace(key, value).second) return BAD_INDEX;
        break;
      }
      case VAL_DOUBLE: {
        double value;
        RETURN_IF_FAILED(parcel->readDouble(&value));
        if (!mDoubleMap.emplace(key, value).second) return BAD_INDEX;
        break;
      }
      case VAL_BOOLEAN: {
        bool value;
        RETURN_IF_FAILED(parcel->readBool(&value));
        if (!mBoolMap.emplace(key, value).second) return BAD_INDEX;
        break;
      }
      case VAL_STRINGARRAY: {
        std::vector<String16> value;
        RETURN_IF_FAILED(parcel->readString16Vector(&value));
        if (!mStringVectorMap.emplace(key, value).second) return BAD_INDEX;
        break;
      }
      case VAL_INTARRAY: {
        std::vector<int32_t> value;
        RETURN_IF_FAILED(parcel->readInt32Vector(&value));
        if (!mIntVectorMap.emplace(key, value).second) return BAD_INDEX;
        break;
      }
      case VAL_LONGARRAY: {
        std::vector<int64_t> value;
        RETURN_IF_FAILED(parcel->readInt64Vector(&value));
        if (!mLongVectorMap.emplace(key, value).second) return BAD_INDEX;
        break;
      }
      case VAL_BOOLEANARRAY: {
        std::vector<bool> value;
        RETURN_IF_FAILED(parcel->readBoolVector(&value));
        if (!mBoolVectorMap.emplace(key, value).second) return BAD_INDEX;
        break;
      }
      case VAL_PERSISTABLEBUNDLE: {
        PersistableBundle value;
        RETURN_IF_FAILED(parcel->readParcelable(&value));
        if (!mPersistableBundleMap.emplace(key, value).second) return BAD_INDEX;
        break;
      }
      case VAL_DOUBLEARRAY: {
        std::vector<double> value;
        RETURN_IF_FAILED(parcel->readDoubleVector(&value));
        if (!mDoubleVectorMap.emplace(key, value).second) return BAD_INDEX;
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
