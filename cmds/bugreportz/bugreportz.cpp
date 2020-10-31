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

#include "bugreportz.h"

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/ProcessState.h>
#include <cutils/android_filesystem_config.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include <future>

using namespace android;
using android::base::StringPrintf;
using android::binder::Status;

static int OpenForWrite(const std::string& filename) {
    return TEMP_FAILURE_RETRY(open(
        filename.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR));
}

std::string DumpstateHelper::GetLocaltimeString() const {
    char date[80];
    time_t t = time(nullptr);
    strftime(date, sizeof(date), "%Y-%m-%d-%H-%M-%S", localtime(&t));
    return std::string(date);
}

std::string DumpstateHelper::GetBasename() const {
    std::string build_id = android::base::GetProperty("ro.build.id", "UNKNOWN_BUILD");
    std::string device_name = android::base::GetProperty("ro.product.name", "UNKNOWN_DEVICE");
    return android::base::StringPrintf("bugreport-%s-%s", device_name.c_str(), build_id.c_str());
}

std::string DumpstateHelper::GetPath(const std::string& suffix) const {
    return android::base::StringPrintf("/bugreports/%s-%s%s", GetBasename().c_str(), date_.c_str(),
                                       suffix.c_str());
}

void DumpstateHelper::CreateParentDirs(const char* path) {
    char* chp = const_cast<char*>(path);

    /* skip initial slash */
    if (chp[0] == '/') chp++;

    /* create leading directories, if necessary */
    struct stat dir_stat;
    while (chp && chp[0]) {
        chp = strchr(chp, '/');
        if (chp) {
            *chp = 0;
            if (stat(path, &dir_stat) == -1 || !S_ISDIR(dir_stat.st_mode)) {
                ALOGI("Creating directory %s\n", path);
                if (mkdir(path, 0770)) { /* drwxrwx--- */
                    ALOGE("Unable to create directory %s: %s\n", path, strerror(errno));
                } else if (chown(path, AID_SHELL, AID_SHELL)) {
                    ALOGE("Unable to change ownership of dir %s: %s\n", path, strerror(errno));
                }
            }
            *chp++ = '/';
        }
    }
}

Status DumpstateHelper::DumpstateListener::onProgress(int32_t progress) {
    if (progress == 0) {
        begin_ = true;
        write(StringPrintf("%s:%s\n", kBEGIN_PREFIX.data(), helper_.bugreport_path_.data()));
    } else {
        write(StringPrintf("%s:%d/100\n", kPROGRESS_PREFIX.data(), progress));
    }
    return Status::ok();
}

Status DumpstateHelper::DumpstateListener::onError(int32_t error_code) {
    std::lock_guard<std::mutex> lock(lock_);
    write(StringPrintf("FAIL:Could not create zip file, check %s for more details. Error code %d\n",
                       helper_.log_path_.data(), error_code));
    helper_.promise_finish_.set_value();
    return Status::ok();
}

Status DumpstateHelper::DumpstateListener::onFinished() {
    std::lock_guard<std::mutex> lock(lock_);
    write(StringPrintf("OK:%s\n", helper_.bugreport_path_.data()));
    helper_.promise_finish_.set_value();
    return Status::ok();
}

Status DumpstateHelper::DumpstateListener::onScreenshotTaken(bool success) {
    std::lock_guard<std::mutex> lock(lock_);
    write(StringPrintf("%s:Result of taking screenshot: %s\n", kPROGRESS_PREFIX.data(),
                       success ? "success" : "failure"));
    return Status::ok();
}

Status DumpstateHelper::DumpstateListener::onUiIntensiveBugreportDumpsFinished(
    const String16& callingpackage) {
    std::lock_guard<std::mutex> lock(lock_);
    write(StringPrintf("%s:Calling package of ui intensive bugreport dumps finished: %s\n",
                       kPROGRESS_PREFIX.data(), String8(callingpackage).c_str()));
    return Status::ok();
}

void DumpstateHelper::DumpstateListener::binderDied(const wp<IBinder>& who) {
    ALOGE("The dumpstate daemon has died [%p]", who.unsafe_get());
    write("FAIL:Binder died. Could not take the bugreport.\n");
    IPCThreadState::self()->stopProcess();
    helper_.promise_finish_.set_value();
}

void DumpstateHelper::DumpstateListener::write(const std::string& line) {
    if (line.empty()) {
        return;
    }
    if (!helper_.show_progress_ && (android::base::StartsWith(line, kPROGRESS_PREFIX)
                                 || android::base::StartsWith(line, kBEGIN_PREFIX))) {
        return;
    }
    android::base::WriteStringToFd(line, helper_.fd_);
}

DumpstateHelper::DumpstateListener::DumpstateListener(DumpstateHelper& helper) : helper_(helper) {
}

sp<android::os::IDumpstateListener> DumpstateHelper::CreateListener() {
    if (!ds_.get()) {
        ALOGE("No dumpstate binder service can be link to death.\n");
        return nullptr;
    }
    // As a Binder server for incoming callbacks we have to initialize the pool.
    ProcessState::self()->startThreadPool();

    sp<DumpstateListener> listener = new DumpstateListener(*this);
    status_t st = IInterface::asBinder(ds_.get())->linkToDeath(listener);
    if (st != NO_ERROR) {
        ALOGE("Unable to register DeathRecipient for IDumpstate\n");
    }
    return listener;
};

sp<android::os::IDumpstate> DumpstateHelper::GetService() {
    sp<os::IDumpstate> ds;
    status_t st = getService(String16("dumpstate"), &ds);
    if (st != OK) {
        ALOGE("Unable to get service binder: 'dumpstate' status=%s\n", statusToString(st).c_str());
    }
    return ds;
};

DumpstateHelper::DumpstateHelper(int fd) noexcept
        : ds_(GetService()), listener_(CreateListener()), fd_(fd) {
    // Ensure parent directories exist, or create it as is.
    CreateParentDirs(bugreport_path_.c_str());
}

int bugreportz(bool show_progress, DumpstateHelper helper) {
    if (!helper.ds_.get() || !helper.listener_.get()) {
        printf("FAIL:Could not initialize dumpstate helper.\n");
        return EXIT_FAILURE;
    }
    helper.show_progress_ = show_progress;

    Status status = helper.ds_->startBugreport(
        /*callingUid=*/AID_SHELL,
        /*callingPackage=*/"",
        android::base::unique_fd(OpenForWrite(helper.bugreport_path_)),
        // Calling with /dev/null instead. Default fd, -1, don't work through binder.
        android::base::unique_fd(OpenForWrite("/dev/null")),
        // In default mode, no notification will show.
        android::os::IDumpstate::BUGREPORT_MODE_DEFAULT, helper.listener_,
        /*isScreenshotRequested=*/false);
    if (!status.isOk()) {
        std::cout << "FAIL:Could not take the bugreport.\n";
        return EXIT_FAILURE;
    }
    helper.promise_finish_.get_future().wait();
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
