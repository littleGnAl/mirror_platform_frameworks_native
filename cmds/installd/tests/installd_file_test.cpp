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

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <gtest/gtest.h>
#include <log/log.h>
#include <stdlib.h>
#include <string.h>

#include "restorable_file.h"
#include "unique_file.h"
#include "utils.h"

#undef LOG_TAG
#define LOG_TAG "installd_file_test"

namespace {

constexpr char kFileTestDir[] = "/data/local/tmp/installd_file_test_data";
constexpr char kTmpFileSuffix[] = ".tmp";

void UnlinkWithAssert(const std::string& path) {
    ASSERT_EQ(0, unlink(path.c_str()));
}

} // namespace

namespace android {
namespace installd {

// Add these as macros as functions make it hard to tell where the failure has happened.
#define ASSERT_FILE_NOT_EXISTING(path)           \
    {                                            \
        struct stat st;                          \
        ASSERT_NE(0, ::stat(path.c_str(), &st)); \
    }
#define ASSERT_FILE_EXISTING(path)               \
    {                                            \
        struct stat st;                          \
        ASSERT_EQ(0, ::stat(path.c_str(), &st)); \
    }
#define ASSERT_FILE_CONTENT(path, expectedContent) ASSERT_EQ(expectedContent, ReadTestFile(path))
#define ASSERT_FILE_OPEN(path, fd)       \
    {                                    \
        fd = open(path.c_str(), O_RDWR); \
        ASSERT_TRUE(fd >= 0);            \
    }
#define ASSERT_WRITE_TO_FD(fd, content) \
    ASSERT_TRUE(android::base::WriteStringToFd(content, android::base::borrowed_fd(fd)))

class FileTest : public testing::Test {
protected:
    virtual void SetUp() {
        setenv("ANDROID_LOG_TAGS", "*:v", 1);
        android::base::InitLogging(nullptr);

        ASSERT_EQ(0, create_dir_if_needed(kFileTestDir, 0777));
    }

    virtual void TearDown() {
        system(android::base::StringPrintf("rm -rf %s", kFileTestDir).c_str());
    }

    std::string GetTestFilePath(const std::string& fileName) {
        return android::base::StringPrintf("%s/%s", kFileTestDir, fileName.c_str());
    }

    void CreateTestFileWithContents(const std::string& path, const std::string& content) {
        ALOGI("CreateTestFileWithContents:%s", path.c_str());
        ASSERT_TRUE(android::base::WriteStringToFile(content, path));
    }

    std::string GetTestName() {
        std::string name(testing::UnitTest::GetInstance()->current_test_info()->name());
        return name;
    }

    std::string ReadTestFile(const std::string& path) {
        std::string content;
        bool r = android::base::ReadFileToString(path, &content);
        if (!r) {
            PLOG(ERROR) << "Cannot read file:" << path;
        }
        return content;
    }
};

TEST_F(FileTest, TestUniqueFileCleanup) {
    std::string testFile = GetTestFilePath(GetTestName());
    CreateTestFileWithContents(testFile, "OriginalContent");

    int fd;
    ASSERT_FILE_OPEN(testFile, fd);

    {
        UniqueFile uf = UniqueFile(fd, testFile, UnlinkWithAssert);

        ASSERT_TRUE(uf.CleanupEnabled());
    }

    ASSERT_FILE_NOT_EXISTING(testFile);
}

TEST_F(FileTest, TestUniqueFileNoCleanup) {
    std::string testFile = GetTestFilePath(GetTestName());
    CreateTestFileWithContents(testFile, "OriginalContent");

    int fd;
    ASSERT_FILE_OPEN(testFile, fd);

    {
        UniqueFile uf = UniqueFile(fd, testFile, UnlinkWithAssert);
        uf.DisableCleanup();

        ASSERT_FALSE(uf.CleanupEnabled());
    }

    ASSERT_FILE_CONTENT(testFile, "OriginalContent");
}

TEST_F(FileTest, TestUniqueFileFd) {
    std::string testFile = GetTestFilePath(GetTestName());
    CreateTestFileWithContents(testFile, "OriginalContent");

    int fd;
    ASSERT_FILE_OPEN(testFile, fd);

    UniqueFile uf = UniqueFile(fd, testFile, UnlinkWithAssert);

    ASSERT_EQ(fd, uf.fd());

    uf.resetFd(-1);

    ASSERT_EQ(-1, uf.fd());
}

TEST_F(FileTest, TestRestorableFileNewFileCleanup) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;

    {
        RestorableFile rf = RestorableFile::CreateWritableFile(testFile, 0600);

        ASSERT_FILE_EXISTING(tmpFile);
        ASSERT_FILE_NOT_EXISTING(testFile);

        ASSERT_WRITE_TO_FD(rf.fd(), "NewContent");

        ASSERT_FILE_CONTENT(tmpFile, "NewContent");
    }

    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_NOT_EXISTING(testFile);
}

TEST_F(FileTest, TestRestorableFileNewFileCleanupWithOriginal) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;
    CreateTestFileWithContents(testFile, "OriginalContent");

    {
        RestorableFile rf = RestorableFile::CreateWritableFile(testFile, 0600);

        ASSERT_FILE_CONTENT(testFile, "OriginalContent");
        ASSERT_FILE_EXISTING(tmpFile);

        ASSERT_WRITE_TO_FD(rf.fd(), "NewContent");

        ASSERT_FILE_CONTENT(tmpFile, "NewContent");
    }

    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_NOT_EXISTING(testFile);
}

TEST_F(FileTest, TestRestorableFileCleanupWithOriginalAndOldTmp) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;
    CreateTestFileWithContents(testFile, "OriginalContent");
    CreateTestFileWithContents(testFile + kTmpFileSuffix, "OldTmp");

    {
        RestorableFile rf = RestorableFile::CreateWritableFile(testFile, 0600);
        ASSERT_WRITE_TO_FD(rf.fd(), "NewContent");

        ASSERT_FILE_CONTENT(testFile, "OriginalContent");
        ASSERT_FILE_CONTENT(tmpFile, "NewContent");
    }

    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_NOT_EXISTING(testFile);
}

TEST_F(FileTest, TestRestorableFileNewFileNoCleanup) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;

    {
        RestorableFile rf = RestorableFile::CreateWritableFile(testFile, 0600);

        ASSERT_FILE_EXISTING(tmpFile);
        ASSERT_FILE_NOT_EXISTING(testFile);

        ASSERT_WRITE_TO_FD(rf.fd(), "NewContent");
        rf.DisableCleanup();

        ASSERT_FILE_CONTENT(tmpFile, "NewContent");
    }

    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_NOT_EXISTING(testFile);
}

TEST_F(FileTest, TestRestorableFileNoCleanupWithOriginal) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;
    CreateTestFileWithContents(testFile, "OriginalContent");

    {
        RestorableFile rf = RestorableFile::CreateWritableFile(testFile, 0600);
        ASSERT_WRITE_TO_FD(rf.fd(), "NewContent");
        rf.DisableCleanup();

        ASSERT_FILE_CONTENT(tmpFile, "NewContent");
        ASSERT_FILE_EXISTING(testFile);
    }

    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_CONTENT(testFile, "OriginalContent");
}

TEST_F(FileTest, TestRestorableFileNoCleanupWithOriginalAndOldTmp) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;
    CreateTestFileWithContents(testFile, "OriginalContent");
    CreateTestFileWithContents(testFile + kTmpFileSuffix, "OldTmp");

    {
        RestorableFile rf = RestorableFile::CreateWritableFile(testFile, 0600);
        ASSERT_WRITE_TO_FD(rf.fd(), "NewContent");
        rf.DisableCleanup();

        ASSERT_FILE_CONTENT(tmpFile, "NewContent");
        ASSERT_FILE_EXISTING(testFile);
    }

    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_CONTENT(testFile, "OriginalContent");
}

TEST_F(FileTest, TestRestorableFileNewFileCommitted) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;

    {
        RestorableFile rf = RestorableFile::CreateWritableFile(testFile, 0600);

        ASSERT_FILE_EXISTING(tmpFile);
        ASSERT_FILE_NOT_EXISTING(testFile);

        ASSERT_WRITE_TO_FD(rf.fd(), "NewContent");
        ASSERT_FILE_CONTENT(tmpFile, "NewContent");

        rf.CommitWorkFile();

        ASSERT_FILE_CONTENT(testFile, "NewContent");
    }

    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_CONTENT(testFile, "NewContent");
}

TEST_F(FileTest, TestRestorableFileCommittedWithOriginal) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;
    CreateTestFileWithContents(testFile, "OriginalContent");

    {
        RestorableFile rf = RestorableFile::CreateWritableFile(testFile, 0600);
        ASSERT_WRITE_TO_FD(rf.fd(), "NewContent");
        ASSERT_FILE_CONTENT(tmpFile, "NewContent");

        rf.CommitWorkFile();

        ASSERT_FILE_CONTENT(testFile, "NewContent");
    }

    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_CONTENT(testFile, "NewContent");
}

TEST_F(FileTest, TestRestorableFileCommittedWithOriginalAndOldTmp) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;
    CreateTestFileWithContents(testFile, "OriginalContent");
    CreateTestFileWithContents(testFile + kTmpFileSuffix, "OldTmp");

    {
        RestorableFile rf = RestorableFile::CreateWritableFile(testFile, 0600);
        ASSERT_WRITE_TO_FD(rf.fd(), "NewContent");
        ASSERT_FILE_CONTENT(tmpFile, "NewContent");

        rf.CommitWorkFile();

        ASSERT_FILE_CONTENT(testFile, "NewContent");
    }

    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_CONTENT(testFile, "NewContent");
}

TEST_F(FileTest, TestRestorableFileRemoveFileAndTmpFileWithContentFile) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;
    CreateTestFileWithContents(testFile, "OriginalContent");

    RestorableFile::RemoveAllFiles(testFile);

    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_NOT_EXISTING(testFile);
}

TEST_F(FileTest, TestRestorableFileRemoveFileAndTmpFileWithContentAndTmpFile) {
    std::string testFile = GetTestFilePath(GetTestName());
    std::string tmpFile = testFile + kTmpFileSuffix;
    CreateTestFileWithContents(testFile, "OriginalContent");
    CreateTestFileWithContents(testFile + kTmpFileSuffix, "TmpContent");

    RestorableFile::RemoveAllFiles(testFile);

    ASSERT_FILE_NOT_EXISTING(tmpFile);
    ASSERT_FILE_NOT_EXISTING(testFile);
}

} // namespace installd
} // namespace android
