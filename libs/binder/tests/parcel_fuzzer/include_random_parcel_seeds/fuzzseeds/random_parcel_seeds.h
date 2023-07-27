/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <android-base/file.h>
#include <android-base/hex.h>
#include <android-base/logging.h>

#include <binder/Binder.h>
#include <binder/Parcel.h>
#include <binder/RecordedTransaction.h>

#include <private/android_filesystem_config.h>

#include <vector>

using android::Parcel;
using android::base::HexString;
using std::vector;

namespace android {

template <typename T>
status_t writeData(base::borrowed_fd fd, const T* data, size_t byteCount);

template <typename T>
void getReversedBytes(uint8_t* reversedData, size_t& len, T min, T max, T val);

template <typename T>
void writeInBuffer(std::vector<std::byte>& integralBuffer, T min, T max, T val);

template <typename T>
void writeInBuffer(std::vector<std::byte>& integralBuffer, T val);

void generateSeedsFromRecording(base::borrowed_fd fd,
                                binder::debug::RecordedTransaction&& transaction);
} // namespace android
