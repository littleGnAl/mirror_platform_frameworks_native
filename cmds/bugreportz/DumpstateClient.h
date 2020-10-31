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

#ifndef FRAMEWORK_NATIVE_CMD_DUMPSTATE_CLIENT_H_
#define FRAMEWORK_NATIVE_CMD_DUMPSTATE_CLIENT_H_

#include <android-base/properties.h>
#include <android/os/BnDumpstateListener.h>
#include <android/os/IDumpstate.h>
#include <android/os/IDumpstateListener.h>

#include <future>

namespace android::os::bugreportz {

class DumpstateClientTest;

class DumpstateClient : public android::os::BnDumpstateListener,
                        public android::IBinder::DeathRecipient {

  public:
    // The client accepts a file descriptor |fd| for showing the progress of
    // the bugreport generation.
    explicit DumpstateClient(int fd) noexcept;
    // For testing.
    DumpstateClient(int fd, sp<android::os::IDumpstate> ds) noexcept;

    binder::Status StartBugreport(bool show_progress);

    status_t WaitForBugreport();

    // Implements BnDumpstateListener.
    binder::Status onProgress(int32_t /*progress*/) override;
    binder::Status onError(int32_t /*error_code*/) override;
    binder::Status onFinished() override;
    binder::Status onScreenshotTaken(bool /*success*/) override;
    binder::Status onUiIntensiveBugreportDumpsFinished(
            const String16& /*calling_package*/) override;

    // Implements IBinder::DeathRecipient.
    void binderDied(const wp<IBinder>& /*who*/) override;

  private:
    friend class DumpstateClientTest;

    // Write the progress to fd when listener callbacks.
    void WriteProgress(const std::string& line) const;

    // A path to bugreport file under the /bugreports folder,
    // for example: "/bugreports/bugreport-<device_name>-<build_id>-<date-time>.zip".
    std::string bugreport_path_;

    // The Dumpstate service proxy to invoke binder call.
    sp<IDumpstate> ds_;

    // A file descriptor for the client to output progress message from the dumpstate.
    int fd_;

    // When not invoked with the -p option to show progress, it must skip BEGIN and PROGRESS lines
    // otherwise it will break adb (which is expecting either OK or FAIL).
    bool show_progress_ = true;

    // A flag indicate that BEGIN message has sent.
    bool begin_msg_sent_ = false;

    // Wait until the value set in onFinish/onError of the listener before termination.
    std::promise<status_t> promise_finish_;
};

} // namespace android::os::bugreportz

#endif  // FRAMEWORK_NATIVE_CMD_DUMPSTATE_CLIENT_H_
