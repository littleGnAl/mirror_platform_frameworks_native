/*
 * Copyright (C) 2021 The Android Open Source Project
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

#ifndef ANDROID_INSTALLD_RESTORABLE_FILE_H
#define ANDROID_INSTALLD_RESTORABLE_FILE_H

#include <functional>
#include <string>

#include "unique_file.h"

namespace android {
namespace installd {

// This is a file abstraction which allows restoring to the original file.
// This file creates a temporary work file and the work file is updated until it is committed.
// Typical flow for this API will be:
// RestorableFile rf =  RestorableFile::CreateWritableFile(...)
// write to file using file descriptor acquired from: rf.fd()
// Make work file into a regular file with: rf.CommitWorkFile()
// Or throw way the work file by destroying the instance without calling CommitWorkFile().
// The temporary work file is closed / removed when an instance is destroyed.
// The original file, if CommitWorkFile() is not called, will be deleted by default. To keep the
// original file, the client should call DisableCleanup().
class RestorableFile {
public:
    RestorableFile();
    RestorableFile(RestorableFile&& other);
    ~RestorableFile();

    // Pass all contents of other file into the current file.
    // Files kept for the current file will be either deleted or committed depending on
    // CommitWorkFile() and DisableCleanUp() calls made before this.
    RestorableFile& operator=(RestorableFile&& other);

    // Get file descriptor for backing work (=temporary) file. If work file does not exist, it will
    // return -1.
    int fd() { return unique_file_.fd(); }

    // Get the path name for the regular file (not temporary file).
    const std::string& path() const { return unique_file_.path(); }

    // Close existing work file and make it regular file.
    // This call effectively disable cleanup. To clean up the regular file, EnableCleanup() should
    // be called after this call.
    void CommitWorkFile();

    // Do not remove regular file after destructor is called.
    void DisableCleanup() { unique_file_.DisableCleanup(); }

    // Close work file, delete it and reset all internal states into default one.
    // If cleanup is enabled, regular file will be also removed.
    void reset();

    // Gets UniqueFile with the same path and fd() pointing to the work file.
    const UniqueFile& GetUniqueFile();

    // Create writable RestorableFile. This involves creating tmp file for writing.
    static RestorableFile CreateWritableFile(const std::string& path, int permissions);

    // Remove the specified file together with tmp file generated as RestorableFile.
    static void RemoveAllFiles(const std::string& path);

private:
    RestorableFile(int value, const std::string& path);
    void CloseWorkFile();

    // Used as a storage for work file fd and path string.
    UniqueFile unique_file_;
};

} // namespace installd
} // namespace android

#endif // ANDROID_INSTALLD_RESTORABLE_FILE_H
