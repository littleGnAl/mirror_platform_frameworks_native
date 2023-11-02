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

#pragma once

#if __has_include(<android-base/file.h>)
#include <android-base/file.h>
#else

#include <binder/unique_fd.h>

#include <string>

#if !defined(_WIN32) && !defined(O_BINARY)
/** Windows needs O_BINARY, but Unix never mangles line endings. */
#define O_BINARY 0
#endif

namespace android::base {

bool ReadFdToString(borrowed_fd fd, std::string* content);
bool WriteStringToFd(std::string_view content, borrowed_fd fd);

bool ReadFully(borrowed_fd fd, void* data, size_t byte_count);
bool WriteFully(borrowed_fd fd, const void* data, size_t byte_count);

#if !defined(_WIN32)
bool Readlink(const std::string& path, std::string* result);
#endif

std::string GetExecutableDirectory();

// Like the regular basename and dirname, but thread-safe on all
// platforms and capable of correctly handling exotic Windows paths.
std::string Basename(std::string_view path);
std::string Dirname(std::string_view path);

} // namespace android::base

#endif // __has_include(<android-base/file.h>)
