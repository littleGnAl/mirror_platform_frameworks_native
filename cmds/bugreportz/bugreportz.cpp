/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include "bugreportz.h"

#include <android-base/file.h>


int bugreportz(bool show_progress,
               android::sp<android::os::bugreportz::DumpstateClient> client) {
    android::binder::Status status = client->StartBugreport(show_progress);
    if (!status.isOk()) {
        printf("FAIL:Could not take the bugreport. (%s)\n", status.toString8().c_str());
        return EXIT_FAILURE;
    }
    client->WaitForBugreport();
    return EXIT_SUCCESS;
}

int bugreportz_stream(int s) {
    while (1) {
        char buffer[65536];
        ssize_t bytes_read = TEMP_FAILURE_RETRY(read(s, buffer, sizeof(buffer)));
        if (bytes_read == 0) {
            break;
        } else if (bytes_read == -1) {
            // EAGAIN really means time out, so change the errno.
            if (errno == EAGAIN) {
                errno = ETIMEDOUT;
            }
            printf("FAIL:Bugreport read terminated abnormally (%s)\n", strerror(errno));
            return EXIT_FAILURE;
        }

        if (!android::base::WriteFully(android::base::borrowed_fd(STDOUT_FILENO), buffer,
                                       bytes_read)) {
            printf("Failed to write data to stdout: trying to send %zd bytes (%s)\n", bytes_read,
                   strerror(errno));
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
