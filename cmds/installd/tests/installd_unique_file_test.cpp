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

#include <stdlib.h>
#include <string.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <gtest/gtest.h>

#include "unique_file.h"
#include "utils.h"

#undef LOG_TAG
#define LOG_TAG "unique_file_test"

namespace {

constexpr char kUniqueFileTestDir[] = "/data/local/tmp/installd_unique_file_test_data";

void UnlinkIgnoreResult(const std::string& path) {
    if (unlink(path.c_str()) < 0) {
        PLOG(ERROR) << "Failed to unlink " << path;
    }
}

} // namespace

namespace android {
namespace installd {

class UniqueFileTest : public testing::Test {
protected:
    virtual void SetUp() {
        setenv("ANDROID_LOG_TAGS", "*:v", 1);
        android::base::InitLogging(nullptr);

        ASSERT_EQ(0, create_dir_if_needed(kUniqueFileTestDir, 0777));
    }

    virtual void TearDown() {
        system(android::base::StringPrintf("rm -rf %s", kUniqueFileTestDir).c_str());
    }

    std::string GetTestFilePath(const std::string& fileName) {
        return android::base::StringPrintf("%s/%s", kUniqueFileTestDir, fileName.c_str());
    }

    void CreateTestFileWithContents(const std::string& fileName, const std::string& content) {
        ASSERT_TRUE(android::base::WriteStringToFile(content, GetTestFilePath(fileName)));
    }

    std::string ReadTestFile(const std::string& fileName) {
        std::string path = GetTestFilePath(fileName);
        std::string content;
        bool r = android::base::ReadFileToString(path, &content);
        if (!r) {
            PLOG(ERROR) << "Cannot read file:" << path;
        }
        return content;
    }

    void WriteToFd(int fd, const std::string& content) {
        ASSERT_TRUE(android::base::WriteStringToFd(content, android::base::borrowed_fd(fd)));
    }

    void AssertFileNotExisting(const std::string& fileName) {
        struct stat st;
        ASSERT_NE(0, ::stat(GetTestFilePath(fileName).c_str(), &st));
    }

    void AssertFileContent(const std::string& fileName, const std::string& expectedContent) {
        ASSERT_EQ(expectedContent, ReadTestFile(fileName));
    }
};

TEST_F(UniqueFileTest, TestUniqueFileNewFileCleanup) {
    std::string testFile("TestUniqueFileNewFileCleanup");

    {
        UniqueFile uf = UniqueFile::CreateWritableFileWithBackup(GetTestFilePath(testFile), 0600,
            UnlinkIgnoreResult);

        AssertFileNotExisting(testFile + ".backup");

        WriteToFd(uf.fd(), "NewContent");
    }

    AssertFileNotExisting(testFile + ".backup");
    AssertFileNotExisting(testFile);
}

TEST_F(UniqueFileTest, TestUniqueFileNewFileCleanupWithBackup) {
    std::string testFile("TestUniqueFileNewFileCleanupWithBackup");
    CreateTestFileWithContents(testFile, "OriginalContent");

    {
        UniqueFile uf = UniqueFile::CreateWritableFileWithBackup(GetTestFilePath(testFile), 0600,
            UnlinkIgnoreResult);

        AssertFileContent(testFile + ".backup", "OriginalContent");

        WriteToFd(uf.fd(), "NewContent");
    }

    AssertFileNotExisting(testFile + ".backup");
    AssertFileContent(testFile, "OriginalContent"); // Backup restored after cleanup
}

TEST_F(UniqueFileTest, TestUniqueFileNewFileNoCleanup) {
    std::string testFile("TestUniqueFileNewFileNoCleanup");

    {
        UniqueFile uf = UniqueFile::CreateWritableFileWithBackup(GetTestFilePath(testFile), 0600);

        AssertFileNotExisting(testFile + ".backup");

        WriteToFd(uf.fd(), "NewContent");
        uf.DisableCleanup(); // NewContent committed
    }

    AssertFileNotExisting(testFile + ".backup");
    AssertFileContent(testFile, "NewContent");
}

TEST_F(UniqueFileTest, TestUniqueFileBackupCleanup) {
    std::string testFile("TestUniqueFileBackupCleanup");
    CreateTestFileWithContents(testFile, "OriginalContent");

    {
        UniqueFile uf = UniqueFile::CreateWritableFileWithBackup(GetTestFilePath(testFile), 0600);
        WriteToFd(uf.fd(), "NewContent");
        uf.DisableCleanup(); // NewContent committed
    }

    AssertFileNotExisting(testFile + ".backup");
    AssertFileContent(testFile, "NewContent");
}

TEST_F(UniqueFileTest, TestUniqueFileBackupCleanupWithOldBackup) {
    std::string testFile("TestUniqueFileBackupCleanupWithOldBackup");
    CreateTestFileWithContents(testFile, "OriginalContent");
    CreateTestFileWithContents(testFile + ".backup", "OldBackup");

    {
        UniqueFile uf = UniqueFile::CreateWritableFileWithBackup(GetTestFilePath(testFile), 0600);
        WriteToFd(uf.fd(), "NewContent");
        uf.DisableCleanup(); // NewContent committed
    }

    AssertFileNotExisting(testFile + ".backup");
    AssertFileContent(testFile, "NewContent");
}

TEST_F(UniqueFileTest, TestUniqueFileBackupNoCleanup) {
    std::string testFile("TestUniqueFileBackupNoCleanup");
    CreateTestFileWithContents(testFile, "OriginalContent");

    {
        UniqueFile uf = UniqueFile::CreateWritableFileWithBackup(GetTestFilePath(testFile), 0600);
        WriteToFd(uf.fd(), "NewContent");
    }

    AssertFileNotExisting(testFile + ".backup");
    AssertFileContent(testFile, "OriginalContent"); // Backup restored
}

TEST_F(UniqueFileTest, TestUniqueFileBackupNoCleanupWithOldBackup) {
    std::string testFile("TestUniqueFileBackupNoCleanupWithOldBackup");
    CreateTestFileWithContents(testFile, "OriginalContent");
    CreateTestFileWithContents(testFile + ".backup", "OldBackup");

    {
        UniqueFile uf = UniqueFile::CreateWritableFileWithBackup(GetTestFilePath(testFile), 0600);
        WriteToFd(uf.fd(), "NewContent");
    }

    AssertFileNotExisting(testFile + ".backup");
    AssertFileContent(testFile, "OriginalContent"); // Backup restored
}

TEST_F(UniqueFileTest, TestUniqueFileRemoveFileAndBackupWithContentFile) {
    std::string testFile("TestUniqueFileRemoveFileAndBackupWithContentFile");
    CreateTestFileWithContents(testFile, "OriginalContent");

    UniqueFile::RemoveFileAndBackup(GetTestFilePath(testFile));

    AssertFileNotExisting(testFile + ".backup");
    AssertFileNotExisting(testFile);
}

TEST_F(UniqueFileTest, TestUniqueFileRemoveFileAndBackupWithContentAbdBackupFile) {
    std::string testFile("TestUniqueFileRemoveFileAndBackupWithContentFile");
    CreateTestFileWithContents(testFile, "OriginalContent");
    CreateTestFileWithContents(testFile + ".backup", "BackupContent");

    UniqueFile::RemoveFileAndBackup(GetTestFilePath(testFile));

    AssertFileNotExisting(testFile + ".backup");
    AssertFileNotExisting(testFile);
}

}  // namespace installd
}  // namespace android
