/*
 * Copyright (C) 2015 The Android Open Source Project
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

#ifndef ANDROID_ERROR_H
#define ANDROID_ERROR_H

#include <cstdint>
#include <string>
#include <ostream>

#include <binder/Parcel.h>
#include <utils/String8.h>

namespace android {
namespace binder {

class Error final {
public:
    // Keep the exception codes in sync with android/os/Parcel.java.
    enum class Exception {
        EX_NONE = 0,
        EX_SECURITY = -1,
        EX_BAD_PARCELABLE = -2,
        EX_ILLEGAL_ARGUMENT = -3,
        EX_NULL_POINTER = -4,
        EX_ILLEGAL_STATE = -5,
        EX_NETWORK_MAIN_THREAD = -6,
        EX_UNSUPPORTED_OPERATION = -7,
        // This is special and Java specific; see Parcel.java.
        EX_HAS_REPLY_HEADER = -128,
        // This is special.  It indicates to clients that their transaction
        // failed at the binder library/driver level.  A server should
        // never write this exception back to the client.
        EX_TRANSACTION_FAILED = -129,
    };

    Error() = default;  // No error by default.
    ~Error() = default;

    status_t readFromParcel(const android::Parcel& parcel);
    status_t writeToParcel(android::Parcel* parcel) const;
    void setFromStatusT(status_t status);

    // Set one of the pre-defined exception types defined above.
    void setException(Exception ex, const android::String8& message);

    // Called by generated code when a method stub returns false, indicating an
    // exception occurred.  Injects an exception if the service has forgotten
    // to do so.[
    void ensureException();

    bool isOk() const { return exception_ == Exception::EX_NONE; }

    // Get information about an exception.  Any argument may be given as
    // nullptr.
    void getException(Exception* returned_exception,
                      android::String8* returned_message) const;
    Exception exception_code() const { return exception_; }
    android::String8 exception_msg() const { return message_; }

    // For logging.
    android::String8 toString8() const;

private:
    // We always write |exception_| as an int32_t to the parcel.
    // If |exception_| != Exception::EX_NONE, we write message as well.
    Exception exception_ = Exception::EX_NONE;
    android::String8 message_;
};  // class Error

}  // namespace binder
}  // namespace android

#endif // ANDROID_ERROR_H
