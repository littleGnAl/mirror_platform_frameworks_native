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

#include <future>

namespace android::os {

namespace {

constexpr char kBEGIN_PREFIX[] = "BEGIN:";
constexpr char kPROGRESS_PREFIX[] = "PROGRESS:";

int OpenForWrite(const std::string& filename) {
    return TEMP_FAILURE_RETRY(open(
            filename.c_str(),
            O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, S_IRUSR | S_IWUSR));
}

sp<IDumpstate> GetService() {
    sp<IDumpstate> ds;
    status_t st = getService(String16("dumpstate"), &ds);
    if (st != OK) {
        ALOGE("Unable to get service binder: 'dumpstate' status=%s\n", statusToString(st).c_str());
    }
    return ds;
}

status_t LinkToDeath(const sp<IDumpstate>& ds,
                     const sp<IBinder::DeathRecipient>& recipient) {
    status_t st = IInterface::asBinder(ds.get())->linkToDeath(recipient);
    if (st != OK) {
        ALOGE("Unable to register DeathRecipient for IDumpstate\n");
    }
    return st;
}

status_t UnlinkToDeath(const sp<IDumpstate>& ds,
                       const sp<IBinder::DeathRecipient>& recipient) {
    status_t st = IInterface::asBinder(ds.get())->unlinkToDeath(recipient);
    if (st != OK) {
        ALOGE("Unable to unregister DeathRecipient for IDumpstate\n");
    }
    return st;
}

void MaybeResolveSymlink(std::string* path) {
    std::string resolved_path;
    if (android::base::Readlink(*path, &resolved_path)) {
        *path = resolved_path;
    }
}

// Create parent directories for a given |path|.
// Keep in sync with `create_parent_dirs()` in dumpstate.
void CreateParentDirs(const char* path) {
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

std::string getBugreportName() {
    std::string bugreport_internal_dir{"/bugreports"};
    MaybeResolveSymlink(&bugreport_internal_dir);

    char date[80];
    time_t t = time(nullptr);
    strftime(date, sizeof(date), "%Y-%m-%d-%H-%M-%S", localtime(&t));
    std::string build_id = base::GetProperty("ro.build.id", "UNKNOWN_BUILD");
    std::string device_name = base::GetProperty("ro.product.name", "UNKNOWN_DEVICE");
    return base::StringPrintf("%s/bugreport-%s-%s-%s.zip",
                              bugreport_internal_dir.c_str(),
                              device_name.c_str(),
                              build_id.c_str(),
                              date);
}

}  // anonymous namespace

namespace bugreportz {

using android::base::StringPrintf;
using android::binder::Status;

Status DumpstateClient::onProgress(int32_t progress) {
    if (progress == 0 && !begin_msg_sent_) {
        begin_msg_sent_ = true;
        WriteProgress(StringPrintf("%s%s\n", kBEGIN_PREFIX, bugreport_path_.data()));
    } else {
        WriteProgress(StringPrintf("%s%d/100\n", kPROGRESS_PREFIX, progress));
    }
    return Status::ok();
}

Status DumpstateClient::onError(int32_t error_code) {
    // TODO(b/16291469) find a better way to reveal log_path to user
    WriteProgress(StringPrintf("FAIL:Could not create zip file, check dumpstate "
                               "log for more details. Error code %d\n", error_code));
    promise_finish_.set_value(error_code);
    return Status::ok();
}

Status DumpstateClient::onFinished() {
    WriteProgress(StringPrintf("OK:%s\n", bugreport_path_.data()));
    promise_finish_.set_value(OK);
    return Status::ok();
}

Status DumpstateClient::onScreenshotTaken(bool success) {
    WriteProgress(StringPrintf("%sResult of taking screenshot: %s\n", kPROGRESS_PREFIX,
                               success ? "success" : "failure"));
    return Status::ok();
}

Status DumpstateClient::onUiIntensiveBugreportDumpsFinished(const String16& callingpackage) {
    WriteProgress(StringPrintf("%sCalling package of ui intensive bugreport dumps finished: %s\n",
                               kPROGRESS_PREFIX, String8(callingpackage).c_str()));
    return Status::ok();
}

void DumpstateClient::binderDied(const wp<IBinder>& /* who */) {
    WriteProgress("FAIL:Binder died. Could not take the bugreport.\n");
    promise_finish_.set_value(IDumpstateListener::BUGREPORT_ERROR_RUNTIME_ERROR);
}

void DumpstateClient::WriteProgress(const std::string& line) const {
    if (line.empty()) {
        return;
    }
    if (!show_progress_ && (base::StartsWith(line, kPROGRESS_PREFIX) ||
                            base::StartsWith(line, kBEGIN_PREFIX))) {
        return;
    }
    android::base::WriteStringToFd(line, fd_);
}

status_t DumpstateClient::WaitForBugreport() {
    UnlinkToDeath(ds_, this);
    return promise_finish_.get_future().get();
}

Status DumpstateClient::StartBugreport(bool show_progress) {
    if (!ds_) {
        WriteProgress("FAIL:Could not initialize dumpstate client properly.\n");
        return Status::fromStatusT(NO_INIT);
    }
    show_progress_ = show_progress;
    // The directory /bugreports symlink to may not exist for a fresh device.
    // Ensure parent directories exist, or create it as is.
    CreateParentDirs(bugreport_path_.c_str());

    LinkToDeath(ds_, this);
    return ds_->startBugreport(
        /*callingUid=*/AID_SHELL,
        /*callingPackage=*/"",
        base::unique_fd(OpenForWrite(bugreport_path_)),
        // Calling with /dev/null instead. Default fd, -1, don't work through binder.
        base::unique_fd(OpenForWrite("/dev/null")),
        // In default mode, no notification will show.
        IDumpstate::BUGREPORT_MODE_DEFAULT,
        /*listener=*/this,
        /*isScreenshotRequested=*/false);
}

DumpstateClient::DumpstateClient(int fd, sp<IDumpstate> ds) noexcept
        : bugreport_path_(getBugreportName()), ds_(std::move(ds)), fd_(fd) {
}

DumpstateClient::DumpstateClient(int fd) noexcept : DumpstateClient(fd, GetService()) {
}

}  // namespace bugreportz
}  // namespace android::os
