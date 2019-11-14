/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "adbwifi/sysdeps/sysdeps.h"

#include <android-base/logging.h>
#include <android-base/unique_fd.h>

namespace adbwifi {
namespace sysdeps {

bool set_file_block_mode(android::base::borrowed_fd fd, bool block) {
    int flags = fcntl(fd.get(), F_GETFL, 0);
    if (flags == -1) {
        PLOG(ERROR) << "failed to fcntl(F_GETFL) for fd " << fd.get();
        return false;
    }
    flags = block ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
    if (fcntl(fd.get(), F_SETFL, flags) != 0) {
        PLOG(ERROR) << "failed to fcntl(F_SETFL) for fd " << fd.get() << ", flags " << flags;
        return false;
    }
    return true;
}

}  //  namespace sysdeps
}  //  namespace adbwifi
