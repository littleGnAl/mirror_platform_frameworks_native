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

#ifndef ANDROID_PERSISTABLE_BUNDLE_H
#define ANDROID_PERSISTABLE_BUNDLE_H

#include <map>
#include <vector>

#include <binder/Parcelable.h>
#include <utils/StrongPointer.h>

namespace android {

class String16;

// C++ implementation of PersistableBundle, a mapping from String values to
// various types that can be saved to persistent and later restored.
class PersistableBundle : public Parcelable {
 public:
  PersistableBundle() = default;
  virtual ~PersistableBundle() = default;

  status_t writeToParcel(Parcel* parcel) const override;
  status_t readFromParcel(const Parcel* parcel) override;

  void putBoolean(const String16& key, bool value);
  void putInt(const String16& key, int32_t value);
  void putLong(const String16& key, int64_t value);
  void putDouble(const String16& key, double value);
  void putString(const String16& key, const String16& value);
  void putBooleanVector(const String16& key, const std::vector<bool>& value);
  void putIntVector(const String16& key, const std::vector<int32_t>& value);
  void putLongVector(const String16& key, const std::vector<int64_t>& value);
  void putDoubleVector(const String16& key, const std::vector<double>& value);
  void putStringVector(const String16& key, const std::vector<String16>& value);
  void putPersistableBundle(const String16& key,
                            const PersistableBundle& value);

  status_t getBoolean(const String16& key, bool* out);
  status_t getInt(const String16& key, int32_t* out);
  status_t getLong(const String16& key, int64_t* out);
  status_t getDouble(const String16& key, double* out);
  status_t getString(const String16& key, String16* out);
  status_t getBooleanVector(const String16& key, std::vector<bool>* out);
  status_t getIntVector(const String16& key, std::vector<int32_t>* out);
  status_t getLongVector(const String16& key, std::vector<int64_t>* out);
  status_t getDoubleVector(const String16& key, std::vector<double>* out);
  status_t getStringVector(const String16& key, std::vector<String16>* out);
  status_t getPersistableBundle(const String16& key, PersistableBundle* out);

 private:
  status_t writeToParcelInner(Parcel* parcel) const;
  status_t readFromParcelInner(const Parcel* parcel, size_t length);

  std::map<String16, bool> bool_map_;
  std::map<String16, int32_t> int_map_;
  std::map<String16, int64_t> long_map_;
  std::map<String16, double> double_map_;
  std::map<String16, String16> string_map_;
  std::map<String16, std::vector<bool>> bool_vector_map_;
  std::map<String16, std::vector<int32_t>> int_vector_map_;
  std::map<String16, std::vector<int64_t>> long_vector_map_;
  std::map<String16, std::vector<double>> double_vector_map_;
  std::map<String16, std::vector<String16>> string_vector_map_;
  std::map<String16, PersistableBundle> persistable_bundle_map_;
};

}  // namespace android

#endif  // ANDROID_PERSISTABLE_BUNDLE_H
