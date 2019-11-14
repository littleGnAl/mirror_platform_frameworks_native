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

#include "adbwifi/crypto/file_utils.h"

#include <adbwifi/sysdeps/sysdeps.h>
#include <android-base/file.h>
#include <android-base/logging.h>

namespace adbwifi {
namespace crypto {

// Tries to replace the |old_file| with |new_file|.
// On success, then |old_file| has been removed and replaced with the
// contents of |new_file|, |new_file| will be removed, and only |old_file| will
// remain.
// On failure, both files will be unchanged.
// |new_file| must exist, but |old_file| does not need to exist.
bool SafeReplaceFile(std::string_view old_file,
                     std::string_view new_file) {
    std::string to_be_deleted(old_file);
    to_be_deleted += ".tbd";

    bool old_renamed = true;
    if (sysdeps::adb_rename(old_file.data(), to_be_deleted.c_str()) != 0) {
        // Don't exit here. This is not necessarily an error, because |old_file|
        // may not exist.
        PLOG(INFO) << "Failed to rename " << old_file;
        old_renamed = false;
    }

    if (sysdeps::adb_rename(new_file.data(), old_file.data()) != 0) {
        PLOG(ERROR) << "Unable to rename file (" << new_file << " => "
                    << old_file << ")";
        if (old_renamed) {
            // Rename the .tbd file back to it's original name
            sysdeps::adb_rename(to_be_deleted.c_str(), old_file.data());
        }
        return false;
    }

    sysdeps::adb_unlink(to_be_deleted.c_str());
    return true;
}

bool DirectoryExists(std::string_view path) {
    struct stat sb;
    return stat(path.data(), &sb) != -1 && S_ISDIR(sb.st_mode);
}

bool FileExists(std::string_view filename) {
    struct stat sb;
    return stat(filename.data(), &sb) != -1 &&
#if defined(_WIN32)
        // Windows version may not handle symlinks correctly.
        S_ISREG(sb.st_mode);
#else
        (S_ISREG(sb.st_mode) || S_ISLNK(sb.st_mode));
#endif
}

}  // namespace crypto
}  // namespace adbwifi
