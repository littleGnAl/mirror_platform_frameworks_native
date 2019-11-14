/*
 * Copyright (C) 2019 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
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

#include <string_view>

namespace adbwifi {
namespace crypto {

// Tries to replace the |old_file| with |new_file|.
// On success, then |old_file| has been removed and replaced with the
// contents of |new_file|, |new_file| will be removed, and only |old_file| will
// remain.
// On failure, both files will be unchanged.
// |new_file| must exist, but |old_file| does not need to exist.
bool SafeReplaceFile(std::string_view old_file,
                     std::string_view new_file);

bool DirectoryExists(std::string_view path);

bool FileExists(std::string_view filename);

}  // namespace crypto
}  // namespace adbwifi
