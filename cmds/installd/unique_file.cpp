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

constexpr char kTmpFileSuffix[] = ".tmp";

std::string GetTmpFilePath(const std::string& path) {
    return android::base::StringPrintf("%s%s", path.c_str(), kTmpFileSuffix);
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
    has_tmp_file_ = other.has_tmp_file_;
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
    if (has_tmp_file_) {  // Has default cleanup behavior
        if (!do_cleanup_) {  // Rename tmp file to path
            if (rename(GetTmpFilePath(path_).c_str(), path_.c_str()) < 0) {
                PLOG(ERROR) << "Cannot rename " << GetTmpFilePath(path_) << " to " << path_;
            }
        }  // Else: need to remove tmp file: handled in later lines
    } else if (do_cleanup_) {
        if (cleanup_ != nullptr) {
            cleanup_(path_);
        }
    }

    // Always try to remove tmp file for valid path.
    if (!path_.empty()) {
        UnlinkPossiblyNonExistingFile(GetTmpFilePath(path_));
    }

    has_tmp_file_ = false;
    value_ = new_value;
    path_ = path;
    cleanup_ = new_cleanup;
}

void UniqueFile::release() {
    value_ = -1;
    path_ = "";
    do_cleanup_ = false;
    has_tmp_file_ = false;
    cleanup_ = nullptr;
}

UniqueFile UniqueFile::CreateWritableFileWithTmpWorkFile(const std::string& path, int permissions) {
    std::string tmp_file_path = GetTmpFilePath(path);
    // If old tmp file exists, delete it.
    UnlinkPossiblyNonExistingFile(tmp_file_path);
    int fd = open(tmp_file_path.c_str(), O_RDWR | O_CREAT, permissions);
    if (fd < 0) {
        PLOG(ERROR) << "Cannot create file: " << path;
    }
    UniqueFile uf(fd, path);
    if (fd >= 0) {
        uf.has_tmp_file_ = true;
    }

    return uf;
}

void UniqueFile::RemoveFileAndTmpFile(const std::string& path) {
    UnlinkPossiblyNonExistingFile(GetTmpFilePath(path));
    UnlinkPossiblyNonExistingFile(path);
}

}  // namespace installd
}  // namespace android
