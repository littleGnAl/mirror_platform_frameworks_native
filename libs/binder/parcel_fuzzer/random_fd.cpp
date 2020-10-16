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

#include <fuzzbinder/random_fd.h>

#include <fcntl.h>

#include <android-base/logging.h>
#include <cutils/ashmem.h>

namespace android {

int getRandomFd(FuzzedDataProvider* provider) {
    int fd = provider->PickValueInArray<std::function<int()>>({
            []() {
                int fd = ashmem_create_region("binder test region", 1024);
                CHECK(fd >= 0) << "invalid ashmem fd: " << strerror(errno);
                return fd;
            },
            []() {
                int fd = open("/dev/null", O_WRONLY);
                CHECK(fd >= 0) << "/dev/null fd err: " << strerror(errno);
                return fd;
            },
    })();
    return fd;
}

} // namespace android
