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

using android::sp;
using android::binder::Status;
using android::os::IDumpstate;
using android::os::IDumpstateListener;
using std::unique_ptr;

namespace android::os::bugreportz {

namespace test {
class TestableDumpstateClient;
}

static constexpr char kBEGIN_PREFIX[] = "BEGIN:";
static constexpr char kPROGRESS_PREFIX[] = "PROGRESS:";

// Interface for binder injection
class IDumpstateFactory {
  public:
    virtual sp<IDumpstate> GetService(const sp<android::IBinder::DeathRecipient>& recipient) = 0;
    virtual ~IDumpstateFactory() = default;
};

class DumpstateClient : public android::os::BnDumpstateListener,
                        public android::IBinder::DeathRecipient {
    friend class test::TestableDumpstateClient;

  public:
    // Client members
    explicit DumpstateClient(int fd) noexcept;
    // For testing
    DumpstateClient(int fd, IDumpstateFactory& factory) noexcept;

    Status StartBugreport(bool show_progress);

    void WaitForBugreportDone();

    // Implements BnDumpstateListener.
    Status onProgress(int32_t /*progress*/) override;
    Status onError(int32_t /*error_code*/) override;
    Status onFinished() override;
    Status onScreenshotTaken(bool /*success*/) override;
    Status onUiIntensiveBugreportDumpsFinished(const android::String16& /*calling_package*/) override;
    // Implements IBinder::DeathRecipient.
    void binderDied(const android::wp<IBinder>& /*who*/) override;

  private:
    class Factory : public IDumpstateFactory {
        sp<IDumpstate> GetService(const sp<android::IBinder::DeathRecipient>& recipient) override;
    };

    // Write to fd when listener callbacks.
    void WriteProgress(const std::string& line) const;

    // Create parent directories for a given |path|.
    // Keep in sync with `create_parent_dirs()` in dumpstate.
    static void CreateParentDirs(const char* /*path*/);

    //
    // Keep the implementations to get bugreport_path_/log_path_ in sync with `PrepareToWriteToFile` in dumpstates'
    //
    // Returns the basename of bugreport file name.
    static std::string GetBasename() ;
    // Returns the name of bugreport file name.
    static std::string GetLocaltimeString() ;
    // Returns the full path of a file with the extension |suffix| based on the
    // `/bugreports` directory, device name, build ID and local time.
    //
    // Note that the implementation is similar to Dumpstate::GetPath except in some
    // bugreport modes, telephony and wifi, it would have an additional infix in the
    // file name.
    std::string GetPath(const std::string& suffix) const;

    std::string bugreport_path_{GetPath(".zip")};
    std::string date_{GetLocaltimeString()};
    // Here don't show dumpstate's real pid, but literal "*" instead.
    std::string log_path_{GetPath("-dumpstate_log-*.txt")};

    // The Dumpstate service proxy to invoke binder call.
    sp<IDumpstate> ds_;

    // As a listener, client writes updates to the file descriptor.
    int fd_;

    // When not invoked with the -p option to show progress, it must skip BEGIN and PROGRESS lines
    // otherwise it will break adb (which is expecting either OK or FAIL).
    bool show_progress_ = true;

    // A flag indicate that BEGIN message has sent.
    bool begin_ = false;
    // Wait until the value set in onFinish/onError of the listener before termination.
    std::promise<void> promise_finish_;

    std::mutex lock_;
};

} // namespace android::os::bugreportz

#endif  // FRAMEWORK_NATIVE_CMD_DUMPSTATE_CLIENT_H_
