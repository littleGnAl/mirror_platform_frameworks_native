// Copyright 2020 Google Inc. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "DumpstateClient.h"

#include <android-base/file.h>
#include <android-base/stringprintf.h>
#include <android-base/strings.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <cutils/android_filesystem_config.h>

#include <functional>
#include <future>
#include <memory>

static int OpenForWrite(const std::string& filename) {
    return TEMP_FAILURE_RETRY(open(
        filename.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR));
}

namespace android::os::bugreportz {

using android::base::StringPrintf;
using android::binder::Status;
using android::os::IDumpstate;
using android::os::IDumpstateListener;

std::string DumpstateClient::GetLocaltimeString() {
    char date[80];
    time_t t = time(nullptr);
    strftime(date, sizeof(date), "%Y-%m-%d-%H-%M-%S", localtime(&t));
    return std::string(date);
}

std::string DumpstateClient::GetBasename() {
    std::string build_id = android::base::GetProperty("ro.build.id", "UNKNOWN_BUILD");
    std::string device_name = android::base::GetProperty("ro.product.name", "UNKNOWN_DEVICE");
    return StringPrintf("bugreport-%s-%s", device_name.c_str(), build_id.c_str());
}

std::string DumpstateClient::GetPath(const std::string& suffix) const {
    return StringPrintf("/bugreports/%s-%s%s", GetBasename().c_str(), date_.c_str(), suffix.c_str());
}

void DumpstateClient::CreateParentDirs(const char* path) {
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

Status DumpstateClient::onProgress(int32_t progress) {
    if (progress == 0) {
        begin_ = true;
        WriteProgress(StringPrintf("%s:%s\n", kBEGIN_PREFIX, bugreport_path_.data()));
    } else {
        WriteProgress(StringPrintf("%s:%d/100\n", kPROGRESS_PREFIX, progress));
    }
    return Status::ok();
}

Status DumpstateClient::onError(int32_t error_code) {
    std::lock_guard<std::mutex> lock(lock_);
    WriteProgress(
        StringPrintf("FAIL:Could not create zip file, check %s for more details. Error code %d\n",
                     log_path_.data(), error_code));
    promise_finish_.set_value();
    return Status::ok();
}

Status DumpstateClient::onFinished() {
    std::lock_guard<std::mutex> lock(lock_);
    WriteProgress(StringPrintf("OK:%s\n", bugreport_path_.data()));
    promise_finish_.set_value();
    return Status::ok();
}

Status DumpstateClient::onScreenshotTaken(bool success) {
    std::lock_guard<std::mutex> lock(lock_);
    WriteProgress(StringPrintf("%s:Result of taking screenshot: %s\n", kPROGRESS_PREFIX,
                               success ? "success" : "failure"));
    return Status::ok();
}

Status DumpstateClient::onUiIntensiveBugreportDumpsFinished(const String16& callingpackage) {
    std::lock_guard<std::mutex> lock(lock_);
    WriteProgress(StringPrintf("%s:Calling package of ui intensive bugreport dumps finished: %s\n",
                               kPROGRESS_PREFIX, String8(callingpackage).c_str()));
    return Status::ok();
}

void DumpstateClient::binderDied(const wp<IBinder>& who) {
    ALOGE("The dumpstate daemon has died [%p]", who.unsafe_get());
    WriteProgress("FAIL:Binder died. Could not take the bugreport.\n");
    IPCThreadState::self()->stopProcess();
    promise_finish_.set_value();
}

void DumpstateClient::WriteProgress(const std::string& line) const {
    if (line.empty()) {
        return;
    }
    if (!show_progress_ && (android::base::StartsWith(line, kPROGRESS_PREFIX) ||
                            android::base::StartsWith(line, kBEGIN_PREFIX))) {
        return;
    }
    android::base::WriteStringToFd(line, fd_);
}

sp<IDumpstate> DumpstateClient::Factory::GetService(
        const sp<android::IBinder::DeathRecipient>& recipient) {
    sp<IDumpstate> ds;
    status_t st = getService(String16("dumpstate"), &ds);
    if (st != OK) {
        ALOGE("Unable to get service binder: 'dumpstate' status=%s\n", statusToString(st).c_str());
    }
    st = IInterface::asBinder(ds.get())->linkToDeath(recipient);
    if (st != OK) {
        ALOGE("Unable to register DeathRecipient for IDumpstate\n");
    }
    return ds;
};

void DumpstateClient::WaitForBugreportDone() {
    promise_finish_.get_future().wait();
}

Status DumpstateClient::StartBugreport(bool show_progress) {
    if (!ds_) {
        printf("FAIL:Could not initialize dumpstate client properly.\n");
        return Status::fromStatusT(NO_INIT);
    }
    show_progress_ = show_progress;
    // Ensure parent directories exist, or create it as is.
    CreateParentDirs(bugreport_path_.c_str());

    return ds_->startBugreport(
        /*callingUid=*/AID_SHELL,
        /*callingPackage=*/"",
        android::base::unique_fd(OpenForWrite(bugreport_path_)),
        // Calling with /dev/null instead. Default fd, -1, don't work through binder.
        android::base::unique_fd(OpenForWrite("/dev/null")),
        // In default mode, no notification will show.
        IDumpstate::BUGREPORT_MODE_DEFAULT,
        /*listener=*/this,
        /*isScreenshotRequested=*/false);
}

DumpstateClient::DumpstateClient(int fd, IDumpstateFactory& factory) noexcept
    : ds_(factory.GetService(this)), fd_(fd) {
}

DumpstateClient::DumpstateClient(int fd) noexcept
    : DumpstateClient(fd, *new Factory) {
}

}  // namespace android::os::bugreportz