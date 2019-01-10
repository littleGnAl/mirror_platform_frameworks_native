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

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "android-base/stringprintf.h"

namespace android {
namespace installd {

bool view_compiler(const char* apk_path, const char* package_name, const char* out_dex_file) {
    pid_t pid = fork();
    if (pid == 0) {
        // viewcompiler won't have permission to open anything, so we have to open the files first
        // and pass file descriptors.

        // Open input file
        int infd = open(apk_path, 0);

        // Set up output file. viewcompiler can't open outputs by fd, but it can write to stdout, so
        // we close stdout and open it towards the right output.
        int outfd = open(out_dex_file, O_CREAT | O_TRUNC | O_WRONLY, 0655);
        fchmod(outfd, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
        close(STDOUT_FILENO);
        dup2(outfd, STDOUT_FILENO);

        // child
        std::string args[] = {"/system/bin/viewcompiler",
                              "--apk",
                              "--infd",
                              android::base::StringPrintf("%d", infd),
                              "--dex",
                              "--package",
                              package_name};
        char* const argv[] = {const_cast<char*>(args[0].c_str()),
                              const_cast<char*>(args[1].c_str()),
                              const_cast<char*>(args[2].c_str()),
                              const_cast<char*>(args[3].c_str()),
                              const_cast<char*>(args[4].c_str()),
                              const_cast<char*>(args[5].c_str()),
                              const_cast<char*>(args[6].c_str()),
                              nullptr};

        execv("/system/bin/viewcompiler", argv);
        exit(1);
    } else {
        int status = 0;
        waitpid(pid, &status, 0);
        return status == 0;
    }
}

} // namespace installd
} // namespace android