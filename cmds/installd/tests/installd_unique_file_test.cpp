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
constexpr char kTmpFileSuffix[] = ".tmp";

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

    void AssertFileExisting(const std::string& fileName) {
        struct stat st;
        ASSERT_EQ(0, ::stat(GetTestFilePath(fileName).c_str(), &st));
    }

    void AssertFileContent(const std::string& fileName, const std::string& expectedContent) {
        ASSERT_EQ(expectedContent, ReadTestFile(fileName));
    }
};

TEST_F(UniqueFileTest, TestUniqueFileNewFileCleanup) {
    std::string testFile("TestUniqueFileNewFileCleanup");

    {
        UniqueFile uf = UniqueFile::CreateWritableFileWithTmpWorkFile(GetTestFilePath(testFile),
            0600);

        AssertFileExisting(testFile + kTmpFileSuffix);
        AssertFileNotExisting(testFile);

        WriteToFd(uf.fd(), "NewContent");

        AssertFileContent(testFile + kTmpFileSuffix, "NewContent");
    }

    AssertFileNotExisting(testFile + kTmpFileSuffix);
    AssertFileNotExisting(testFile);
}

TEST_F(UniqueFileTest, TestUniqueFileNewFileCleanupWithOriginal) {
    std::string testFile("TestUniqueFileNewFileCleanupWithOriginal");
    CreateTestFileWithContents(testFile, "OriginalContent");

    {
        UniqueFile uf = UniqueFile::CreateWritableFileWithTmpWorkFile(GetTestFilePath(testFile),
            0600);

        AssertFileContent(testFile, "OriginalContent");
        AssertFileExisting(testFile + kTmpFileSuffix);

        WriteToFd(uf.fd(), "NewContent");

        AssertFileContent(testFile + kTmpFileSuffix, "NewContent");
    }

    AssertFileNotExisting(testFile + kTmpFileSuffix);
    AssertFileContent(testFile, "OriginalContent"); // Original kept after cleanup
}

TEST_F(UniqueFileTest, TestUniqueFileCleanupWithOriginalAndOldTmp) {
    std::string testFile("TestUniqueFileCleanupWithOriginalAndOldTmp");
    CreateTestFileWithContents(testFile, "OriginalContent");
    CreateTestFileWithContents(testFile + kTmpFileSuffix, "OldTmp");

    {
        UniqueFile uf = UniqueFile::CreateWritableFileWithTmpWorkFile(GetTestFilePath(testFile),
            0600);
        WriteToFd(uf.fd(), "NewContent");

        AssertFileContent(testFile, "OriginalContent");
        AssertFileContent(testFile + kTmpFileSuffix, "NewContent");
    }

    AssertFileNotExisting(testFile + kTmpFileSuffix);
    AssertFileContent(testFile, "OriginalContent");
}

TEST_F(UniqueFileTest, TestUniqueFileNewFileNoCleanup) {
    std::string testFile("TestUniqueFileNewFileNoCleanup");

    {
        UniqueFile uf = UniqueFile::CreateWritableFileWithTmpWorkFile(GetTestFilePath(testFile),
            0600);

        AssertFileExisting(testFile + kTmpFileSuffix);
        AssertFileNotExisting(testFile);

        WriteToFd(uf.fd(), "NewContent");
        uf.DisableCleanup(); // NewContent committed

        AssertFileContent(testFile + kTmpFileSuffix, "NewContent");
    }

    AssertFileNotExisting(testFile + kTmpFileSuffix);
    AssertFileContent(testFile, "NewContent");
}

TEST_F(UniqueFileTest, TestUniqueFileNoCleanupWithOriginal) {
    std::string testFile("TestUniqueFileNoCleanupWithOriginal");
    CreateTestFileWithContents(testFile, "OriginalContent");

    {
        UniqueFile uf = UniqueFile::CreateWritableFileWithTmpWorkFile(GetTestFilePath(testFile),
            0600);
        WriteToFd(uf.fd(), "NewContent");
        uf.DisableCleanup(); // NewContent committed

        AssertFileContent(testFile + kTmpFileSuffix, "NewContent");
        AssertFileExisting(testFile);
    }

    AssertFileNotExisting(testFile + kTmpFileSuffix);
    AssertFileContent(testFile, "NewContent");
}

TEST_F(UniqueFileTest, TestUniqueFileNoCleanupWithOriginalAndOldTmp) {
    std::string testFile("TestUniqueFileNoCleanupWithOriginalAndOldTmp");
    CreateTestFileWithContents(testFile, "OriginalContent");
    CreateTestFileWithContents(testFile + kTmpFileSuffix, "OldTmp");

    {
        UniqueFile uf = UniqueFile::CreateWritableFileWithTmpWorkFile(GetTestFilePath(testFile),
            0600);
        WriteToFd(uf.fd(), "NewContent");
        uf.DisableCleanup(); // NewContent committed

        AssertFileContent(testFile + kTmpFileSuffix, "NewContent");
        AssertFileExisting(testFile);
    }

    AssertFileNotExisting(testFile + kTmpFileSuffix);
    AssertFileContent(testFile, "NewContent");
}

TEST_F(UniqueFileTest, TestUniqueFileRemoveFileAndTmpFileWithContentFile) {
    std::string testFile("TestUniqueFileRemoveFileAndTmpFileWithContentFile");
    CreateTestFileWithContents(testFile, "OriginalContent");

    UniqueFile::RemoveFileAndTmpFile(GetTestFilePath(testFile));

    AssertFileNotExisting(testFile + kTmpFileSuffix);
    AssertFileNotExisting(testFile);
}

TEST_F(UniqueFileTest, TestUniqueFileRemoveFileAndTmpFileWithContentAndTmpFile) {
    std::string testFile("TestUniqueFileRemoveFileAndTmpFileWithContentAndTmpFile");
    CreateTestFileWithContents(testFile, "OriginalContent");
    CreateTestFileWithContents(testFile + kTmpFileSuffix, "TmpContent");

    UniqueFile::RemoveFileAndTmpFile(GetTestFilePath(testFile));

    AssertFileNotExisting(testFile + kTmpFileSuffix);
    AssertFileNotExisting(testFile);
}

}  // namespace installd
}  // namespace android
