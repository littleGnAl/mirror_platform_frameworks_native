/*
 * Copyright (C) 2020 The Android Open Source Project
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

#include "unique_file.h"

#include <string>

#include <fcntl.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/stringprintf.h>

namespace {

constexpr char kBackupFileSuffix[] = ".backup";

std::string GetBackupFilePath(const std::string& path) {
    return android::base::StringPrintf("%s%s", path.c_str(), kBackupFileSuffix);
}

void UnlinkPossiblyNonExistingFile(const std::string& path) {
    if (unlink(path.c_str()) < 0) {
        if (errno != ENOENT && errno != EROFS) {  // EROFS reported even if it does not exist.
            PLOG(ERROR) << "Cannot unlink: " << path;
        }
    }
}

}  // namespace

namespace android {
namespace installd {

UniqueFile::UniqueFile() : UniqueFile(-1, "") {}

UniqueFile::UniqueFile(int value, std::string path) : UniqueFile(value, path, nullptr) {}

UniqueFile::UniqueFile(int value, std::string path, CleanUpFunction cleanup)
        : value_(value), path_(path), cleanup_(cleanup), do_cleanup_(true), auto_close_(true) {}

UniqueFile::UniqueFile(UniqueFile&& other) {
    *this = std::move(other);
}

UniqueFile::~UniqueFile() {
    reset();
}

UniqueFile& UniqueFile::operator=(UniqueFile&& other) {
    value_ = other.value_;
    path_ = other.path_;
    cleanup_ = other.cleanup_;
    do_cleanup_ = other.do_cleanup_;
    auto_close_ = other.auto_close_;
    has_backup_file_ = other.has_backup_file_;
    other.release();
    return *this;
}

void UniqueFile::reset() {
    reset(-1, "");
}

void UniqueFile::reset(int new_value, const std::string& path, CleanUpFunction new_cleanup) {
    if (auto_close_ && value_ >= 0) {
        if (close(value_) < 0) {
            PLOG(ERROR) << "Failed to close fd " << value_ << ", with path: " << path;
        }
    }
    if (do_cleanup_) {
        if (cleanup_ != nullptr) {
            cleanup_(path_);
        }
        // Restore backup file if it exists
        if (has_backup_file_) {
            if (rename(GetBackupFilePath(path_).c_str(), path_.c_str()) < 0) {
                PLOG(ERROR) << "Cannot rename " << GetBackupFilePath(path_) << " to " << path_;
            }
        }
    }

    // Always try to remove Backup file for valid path.
    if (!path_.empty()) {
        UnlinkPossiblyNonExistingFile(GetBackupFilePath(path_));
    }

    has_backup_file_ = false;
    value_ = new_value;
    path_ = path;
    cleanup_ = new_cleanup;
}

void UniqueFile::release() {
    value_ = -1;
    path_ = "";
    do_cleanup_ = false;
    has_backup_file_ = false;
    cleanup_ = nullptr;
}

UniqueFile UniqueFile::CreateWritableFileWithBackup(const std::string& path, int permissions,
        CleanUpFunction cleanup) {
    std::string backup_file_path = GetBackupFilePath(path);
    // If old backup file exists, delete it.
    UnlinkPossiblyNonExistingFile(backup_file_path);
    // Old file may not exist. In that case, there is no backup.
    bool has_backup = false;
    if (rename(path.c_str(), backup_file_path.c_str()) == 0) {
        has_backup = true;
    } else if (errno != ENOENT) {  // Ignore if it does not exist.
        PLOG(ERROR) << "Cannot rename " << path << " to " << backup_file_path;
    }
    int fd = open(path.c_str(), O_RDWR | O_CREAT, permissions);
    if (fd < 0) {
        PLOG(ERROR) << "Cannot create file: " << path;
    }
    UniqueFile uf(fd, path, cleanup);
    uf.has_backup_file_ = has_backup;

    return uf;
}

void UniqueFile::RemoveFileAndBackup(const std::string& path) {
    UnlinkPossiblyNonExistingFile(GetBackupFilePath(path));
    UnlinkPossiblyNonExistingFile(path);
}

}  // namespace installd
}  // namespace android
