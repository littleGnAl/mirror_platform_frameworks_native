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

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>

#include <gtest/gtest.h>
#include <sys/mman.h>
#include <poll.h>

#define BINDER_DEV_NAME "/dev/binder"

testing::Environment* binder_env;

#define BinderDriverInterfaceTestEnv BinderDriverInterfaceTestEnv32
#define BinderDriverInterfaceTest BinderDriverInterfaceTest32
#define BINDER_IPC_32BIT 1
#include "binderDriverInterfaceTest_inc.cpp"
#undef BINDER_IPC_32BIT
#undef BinderDriverInterfaceTestEnv
#undef BinderDriverInterfaceTest

#define BinderDriverInterfaceTestEnv BinderDriverInterfaceTestEnv64
#define BinderDriverInterfaceTest BinderDriverInterfaceTest64
#define BINDER_IPC_32BIT 0
#include "binderDriverInterfaceTest_inc.cpp"
#undef BINDER_IPC_32BIT
#undef BinderDriverInterfaceTestEnv
#undef BinderDriverInterfaceTest

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    if (argc >= 2 && !strcmp(argv[1], "32"))
      binder_env =
          AddGlobalTestEnvironment(new BinderDriverInterfaceTestEnv32());
    else
      binder_env =
          AddGlobalTestEnvironment(new BinderDriverInterfaceTestEnv64());
    return RUN_ALL_TESTS();
}
