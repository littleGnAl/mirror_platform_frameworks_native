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
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android/os/BnDumpstate.h>
#include <android/os/BnDumpstateListener.h>
#include <android/os/IDumpstate.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <errno.h>
#include <private/android_filesystem_config.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <string>

using namespace android;

class DumpstateListener : public android::os::BnDumpstateListener {
  public:
    DumpstateListener(bool show_progress, int fd) : out_fd_(fd), show_progress_(show_progress) {
    }

    binder::Status onProgress(int32_t progress) override {
        dprintf(out_fd_, "PROGRESS:In progress %d, show=%d", progress, show_progress_);
        return binder::Status::ok();
    }

    binder::Status onError(int32_t error_code) override {
        std::lock_guard<std::mutex> lock(lock_);
        error_code_ = error_code;
        dprintf(out_fd_, "FAIL:Error code %d, check log for more details", error_code);
        return binder::Status::ok();
    }

    binder::Status onFinished() override {
        std::lock_guard<std::mutex> lock(lock_);
        is_finished_ = true;
        dprintf(out_fd_, "OK:Finished");
        return binder::Status::ok();
    }

    binder::Status onScreenshotTaken(bool success) override {
        std::lock_guard<std::mutex> lock(lock_);
        dprintf(out_fd_, "PROGRESS:Result of taking screenshot: %s",
                success ? "success" : "failure");
        return binder::Status::ok();
    }

    binder::Status onUiIntensiveBugreportDumpsFinished(
        const android::String16& callingpackage) override {
        std::lock_guard<std::mutex> lock(lock_);
        std::string callingpackageUtf8 = std::string(String8(callingpackage).string());
        dprintf(out_fd_, "PROGRESS:Calling package of ui intensive bugreport dumps finished: %s",
                callingpackageUtf8.c_str());
        return binder::Status::ok();
    }

    bool getIsFinished() {
        std::lock_guard<std::mutex> lock(lock_);
        return is_finished_;
    }

    int getErrorCode() {
        std::lock_guard<std::mutex> lock(lock_);
        return error_code_;
    }

  private:
    int out_fd_;
    int error_code_ = -1;
    bool is_finished_ = false;
    bool show_progress_ = false;
    std::mutex lock_;
};

int OpenForWrite(const std::string& filename) {
    return TEMP_FAILURE_RETRY(open(filename.c_str(),
                                   O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                                   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));
}

void WaitTillExecutionComplete(DumpstateListener* listener) {
    static constexpr int kBugreportTimeoutSeconds = 120;
    int i = 0;
    while (!listener->getIsFinished() && listener->getErrorCode() == -1 &&
           i < kBugreportTimeoutSeconds) {
        sleep(1);
        i++;
    }
}

int bugreportd(bool show_progress) {
    auto ds = waitForService<android::os::IDumpstate>(String16("dumpstate"));

    // TODO parameterize file name
    // TODO create parent dirs
    android::base::unique_fd bugreport_fd(OpenForWrite("/bugreports/tmp.zip"));
    android::base::unique_fd screenshot_fd(OpenForWrite("/bugreports/tmp.png"));
    sp<DumpstateListener> listener(new DumpstateListener(show_progress, dup(STDOUT_FILENO)));
    printf("PROGRESS:startBugreport from brz.\n");
    android::binder::Status status = ds->startBugreport(
        /* callingUid= */ AID_SHELL, /* callingPackage= */ "", std::move(bugreport_fd),
        std::move(screenshot_fd), android::os::IDumpstate::BUGREPORT_MODE_FULL, listener,
        /* isScreenshotRequested= */ false);
    if (!status.isOk()) {
        printf("FAIL:Could not take the bugreport.\n");
        return EXIT_FAILURE;
    }
    WaitTillExecutionComplete(listener.get());
    return EXIT_SUCCESS;
}

static constexpr char BEGIN_PREFIX[] = "BEGIN:";
static constexpr char PROGRESS_PREFIX[] = "PROGRESS:";

static void write_line(const std::string& line, bool show_progress) {
    if (line.empty()) return;

    // When not invoked with the -p option, it must skip BEGIN and PROGRESS lines otherwise it
    // will break adb (which is expecting either OK or FAIL).
    if (!show_progress && (android::base::StartsWith(line, PROGRESS_PREFIX) ||
                           android::base::StartsWith(line, BEGIN_PREFIX)))
        return;

    android::base::WriteStringToFd(line, STDOUT_FILENO);
}

int bugreportz(int s, bool show_progress) {
    std::string line;
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

        // Writes line by line.
        for (int i = 0; i < bytes_read; i++) {
            char c = buffer[i];
            line.append(1, c);
            if (c == '\n') {
                write_line(line, show_progress);
                line.clear();
            }
        }
    }
    // Process final line, in case it didn't finish with newline
    write_line(line, show_progress);
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

        if (!android::base::WriteFully(android::base::borrowed_fd(STDOUT_FILENO), buffer, bytes_read)) {
            printf("Failed to write data to stdout: trying to send %zd bytes (%s)\n",
                bytes_read, strerror(errno));
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
