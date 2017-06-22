/*
 * Copyright (C) 2014 The Android Open Source Project
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

#include <string.h>

#include <gtest/gtest.h>

testing::Environment* getBinderDriverInterfaceTestEnv32();
testing::Environment* getBinderDriverInterfaceTestEnv64();
testing::Environment* binder_env;

#define BinderDriverInterfaceTestEnv BinderDriverInterfaceTestEnv64
#define BinderDriverInterfaceTest BinderDriverInterfaceTest64
#define getBinderDriverInterfaceTestEnv getBinderDriverInterfaceTestEnv64
#include "binderDriverInterfaceTest_inc.cpp"


int main(int argc, char **argv) {
    testing::InitGoogleTest(&argc, argv);
    bool is_32 = false;
    for (int index = 0; index < argc; index++) {
        if (!strcmp(argv[index], "32")) {
            is_32 = true;
            break;
        }
    }
    std::string bit_filter;
    if (is_32) {
        bit_filter = "BinderDriverInterfaceTest64*";
        binder_env = AddGlobalTestEnvironment(
                getBinderDriverInterfaceTestEnv32());
    } else {
        bit_filter = "BinderDriverInterfaceTest32*";
        binder_env = AddGlobalTestEnvironment(
                getBinderDriverInterfaceTestEnv64());
    }
    size_t minus_pos = testing::GTEST_FLAG(filter).find("-");
    if (minus_pos == std::string::npos) {
        testing::GTEST_FLAG(filter) += "-" + bit_filter;
    } else {
        testing::GTEST_FLAG(filter).insert(minus_pos + 1, bit_filter + ":");
    }
    return RUN_ALL_TESTS();
}
