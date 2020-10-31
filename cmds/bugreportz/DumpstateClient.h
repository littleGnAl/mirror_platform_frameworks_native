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
    /**
     * The client prepares `bugreport_path_`, the zip file path, for later API call.
     *
     * Keep the implementations to get bugreport_path_ in sync with dumpstate's
     * `PrepareToWriteToFile`. Note that the path is similar to the result of
     * Dumpstate::GetPath except in some bugreport modes, telephony and wifi,
     * that would have an additional infix in it.
     */
    explicit DumpstateClient(int fd) noexcept;
    // For testing.
    DumpstateClient(int fd, sp<android::os::IDumpstate> ds) noexcept;

    binder::Status StartBugreport(bool show_progress);

    void WaitForBugreport();

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

    std::string bugreport_path_;

    // The Dumpstate service proxy to invoke binder call.
    sp<IDumpstate> ds_;

    // As a listener, client writes updates to the file descriptor.
    int fd_;

    // When not invoked with the -p option to show progress, it must skip BEGIN and PROGRESS lines
    // otherwise it will break adb (which is expecting either OK or FAIL).
    bool show_progress_ = true;

    // A flag indicate that BEGIN message has sent.
    bool begin_msg_sent_ = false;

    // Wait until the value set in onFinish/onError of the listener before termination.
    std::promise<void> promise_finish_;

    std::mutex lock_;
};

} // namespace android::os::bugreportz

#endif  // FRAMEWORK_NATIVE_CMD_DUMPSTATE_CLIENT_H_
