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
#define LOG_TAG "bugreportz"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <future>
#include <string>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/strings.h>
#include <android-base/stringprintf.h>
#include <android/os/BnDumpstate.h>
#include <android/os/BnDumpstateListener.h>
#include <android/os/IDumpstate.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <log/log.h>
#include <private/android_filesystem_config.h>

#include "bugreportz.h"

using namespace android;
using android::base::StringPrintf;

static constexpr char BEGIN_PREFIX[] = "BEGIN:";
static constexpr char PROGRESS_PREFIX[] = "PROGRESS:";

static void write_line(int fd, const std::string& line, bool show_progress) {
    if (line.empty()) return;

    // When not invoked with the -p option, it must skip BEGIN and PROGRESS lines otherwise it
    // will break adb (which is expecting either OK or FAIL).
    if (!show_progress && (android::base::StartsWith(line, PROGRESS_PREFIX) ||
                           android::base::StartsWith(line, BEGIN_PREFIX)))
        return;

    android::base::WriteStringToFd(line, fd);
}

class DumpstateListener : public android::os::BnDumpstateListener {
  public:
    DumpstateListener(bool show_progress, int fd, std::promise<void>&& p)
        : out_fd_(fd), show_progress_(show_progress), pr_(std::move(p)) {
    }

    binder::Status onProgress(int32_t progress) override {
        if (progress == 0) {
            // TODO: BEGIN:%path_%\n
            write_line(StringPrintf("BEGIN:show=%d\n", show_progress_));
        } else {
            write_line(StringPrintf("PROGRESS:%d/100\n", progress));
        }
        return binder::Status::ok();
    }

    binder::Status onError(int32_t error_code) override {
        std::lock_guard<std::mutex> lock(lock_);
        // TODO: check %ds.log_path_%
        write_line(StringPrintf(
            "FAIL:could not create zip file, check log for more details. error code %d\n",
             error_code));
        pr_.set_value();
        return binder::Status::ok();
    }

    binder::Status onFinished() override {
        std::lock_guard<std::mutex> lock(lock_);
        // TODO: OK:%final_path%\n
        write_line("OK:Finished\n");
        pr_.set_value();
        return binder::Status::ok();
    }

    binder::Status onScreenshotTaken(bool success) override {
        std::lock_guard<std::mutex> lock(lock_);
        write_line(StringPrintf(
            "PROGRESS:Result of taking screenshot: %s\n",
            success ? "success" : "failure"));
        return binder::Status::ok();
    }

    binder::Status onUiIntensiveBugreportDumpsFinished(
        const android::String16& callingpackage) override {
        std::lock_guard<std::mutex> lock(lock_);
        write_line(StringPrintf(
            "PROGRESS:Calling package of ui intensive bugreport dumps finished: %s\n",
            String8(callingpackage).c_str()));
        return binder::Status::ok();
    }

  private:
    int out_fd_;
    bool show_progress_ = false;
    std::mutex lock_;
    std::promise<void> pr_;

    void write_line(const std::string& line) {
        return ::write_line(out_fd_, line, show_progress_);
    }
};

int OpenForWrite(const std::string& filename) {
    return TEMP_FAILURE_RETRY(open(filename.c_str(),
                                   O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                                   S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH));
}

int bugreportz(bool show_progress) {
    ProcessState::self()->startThreadPool();
	sp<IBinder> binder = defaultServiceManager()->getService(String16("dumpstate"));
    auto ds = interface_cast<android::os::IDumpstate>(binder);

    std::promise<void> p;
    std::future<void> future_done = p.get_future();

    // TODO prepare file name create parent dirs
    android::base::unique_fd bugreport_fd(OpenForWrite("/bugreports/tmp.zip"));
    android::base::unique_fd screenshot_fd(OpenForWrite("/bugreports/tmp.png"));
    sp<DumpstateListener> listener(new DumpstateListener(show_progress, dup(STDOUT_FILENO), std::move(p)));
    binder::Status status = ds->startBugreport(
        /* callingUid= */ AID_SHELL, /* callingPackage= */ "", std::move(bugreport_fd),
        std::move(screenshot_fd), android::os::IDumpstate::BUGREPORT_MODE_FULL, listener,
        /* isScreenshotRequested= */ false);
    if (!status.isOk()) {
        printf("FAIL:Could not take the bugreport.\n");
        return EXIT_FAILURE;
    }
    future_done.wait();
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
