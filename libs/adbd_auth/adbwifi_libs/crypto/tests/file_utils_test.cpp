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

#include <gtest/gtest.h>

#include <adbwifi/crypto/file_utils.h>
#include <adbwifi/sysdeps/sysdeps.h>
#include <android-base/file.h>

namespace adbwifi {
namespace crypto {

TEST(AdbWifiCryptoFileUtilsTest, FileExists) {
    EXPECT_FALSE(FileExists("IDontExist"));
    TemporaryFile file;
    EXPECT_TRUE(FileExists(file.path));
    TemporaryDir dir;
    EXPECT_FALSE(FileExists(dir.path));
}

TEST(AdbWifiCryptoFileUtilsTest, DirectoryExists) {
    std::string path;
    {
        TemporaryDir temp_dir;
        path = temp_dir.path;
        EXPECT_TRUE(DirectoryExists(path));
    }
    {
        TemporaryFile file;
        EXPECT_FALSE(DirectoryExists(file.path));
    }
    // Directory was removed.
    EXPECT_FALSE(DirectoryExists(path));
}

TEST(AdbWifiCryptoFileUtilsTest, SafeReplaceFile) {
    std::string msgA = "Message A";
    std::string msgB = "Message B";

    // Should not work with non-existant files.
    EXPECT_FALSE(SafeReplaceFile("OldIDontExist", "NewIDontExist"));

    {
        // Should not work if new file doesn't exist
        TemporaryFile old;
        EXPECT_FALSE(SafeReplaceFile(old.path, "NewIDontExist"));
        // Make sure it didn't remove the old file
        EXPECT_TRUE(FileExists(old.path));
    }

    {
        // Should work if new file exists, but old file doesn't
        TemporaryFile old_file;
        sysdeps::adb_unlink(old_file.path);
        ASSERT_FALSE(FileExists(old_file.path));

        TemporaryFile new_file;
        EXPECT_TRUE(android::base::WriteStringToFile(msgA, new_file.path));

        EXPECT_TRUE(SafeReplaceFile(old_file.path, new_file.path));
        // new_file should have been removed
        EXPECT_FALSE(FileExists(new_file.path));
        // old_file should exist
        EXPECT_TRUE(FileExists(old_file.path));

        std::string content;
        EXPECT_TRUE(android::base::ReadFileToString(old_file.path, &content));
        EXPECT_STREQ(content.c_str(), msgA.c_str());
    }

    {
        // Should work if both files exist
        TemporaryFile old_file;
        EXPECT_TRUE(android::base::WriteStringToFile(msgA, old_file.path));
        TemporaryFile new_file;
        EXPECT_TRUE(android::base::WriteStringToFile(msgB, new_file.path));

        EXPECT_TRUE(SafeReplaceFile(old_file.path, new_file.path));
        // new_file should have been removed
        EXPECT_FALSE(FileExists(new_file.path));
        // old_file should exist
        EXPECT_TRUE(FileExists(old_file.path));

        std::string content;
        EXPECT_TRUE(android::base::ReadFileToString(old_file.path, &content));
        EXPECT_STREQ(content.c_str(), msgB.c_str());
    }
}

}  // namespace crypto
}  // namespace adbwifi
