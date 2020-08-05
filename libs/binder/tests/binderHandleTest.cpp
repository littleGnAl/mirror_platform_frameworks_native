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

#include <android-base/logging.h>
#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <binder/IServiceManager.h>

#include <unistd.h>
#include <sys/prctl.h>

int main(int argc, char** argv) {
    (void) argc;
    (void) argv;

    for (size_t my_tea = 0; my_tea < 23; ++my_tea) {
        if (fork() != 0) continue;

        // cleanup child processes - dc this is racey for test
        prctl(PR_SET_PDEATHSIG, SIGHUP);

        CHECK(::android::OK == ::android::defaultServiceManager()->addService(
            ::android::String16("you-really-got-a-hold-on-me"),
            new ::android::BBinder()));

        // NO :(){ :|:& };:
        exit(0);
    }

    sleep(1); // dc for test - just give child processes enough time to wait
    return EXIT_SUCCESS;
}
