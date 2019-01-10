/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include "view_compiler.h"

#include <string>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace android {
namespace installd {

bool view_compiler(const char* apk_path, const char* package_name, const char* out_dex_file) {
    pid_t pid = fork();
    if (pid == 0) {
        // child
        std::string args[] = {"/system/bin/viewcompiler",
                              "--apk",
                              apk_path,
                              "--package",
                              package_name,
                              "--out",
                              out_dex_file};
        char* const argv[] = {const_cast<char*>(args[0].c_str()),
                              const_cast<char*>(args[1].c_str()),
                              const_cast<char*>(args[2].c_str()),
                              const_cast<char*>(args[3].c_str()),
                              const_cast<char*>(args[4].c_str()),
                              const_cast<char*>(args[5].c_str()),
                              const_cast<char*>(args[6].c_str()),
                              nullptr};

        execv("/system/bin/viewcompiler", argv);
        return false;
    } else {
        int status = 0;
        waitpid(pid, &status, 0);
        return status == 0;
    }
}

} // namespace installd
} // namespace android