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

#ifndef ANDROID_BINDER_STATUS_H
#define ANDROID_BINDER_STATUS_H

#include <cstdint>

#include <binder/Parcel.h>
#include <utils/String8.h>

namespace android {
namespace binder {

// An object similar in function to a status_t except that it understands
// how exceptions are encoded in the prefix of a Parcel. Used like:
//
//     Parcel data;
//     Parcel reply;
//     status_t status;
//     binder::Status remote_exception;
//     if ((status = data.writeInterfaceToken(interface_descriptor)) != OK ||
//         (status = data.writeInt32(function_input)) != OK) {
//         // We failed to write into the memory of our local parcel?
//     }
//     if ((status = remote()->transact(transaction, data, &reply)) != OK) {
//        // Something has gone wrong in the binder driver or libbinder.
//     }
//     if ((status = remote_exception.readFromParcel(reply)) != OK) {
//         // The remote didn't correctly write the exception header to the
//         // reply.
//     }
//     if (!remote_exception.isOk()) {
//         // The transaction went through correctly, but the remote reported an
//         // exception during handling.
//     }
//
class Status final {
public:
    // Keep the exception codes in sync with android/os/Parcel.java.
    enum Exception {
        EX_NONE = 0,
        EX_SECURITY = -1,
        EX_BAD_PARCELABLE = -2,
        EX_ILLEGAL_ARGUMENT = -3,
        EX_NULL_POINTER = -4,
        EX_ILLEGAL_STATE = -5,
        EX_NETWORK_MAIN_THREAD = -6,
        EX_UNSUPPORTED_OPERATION = -7,
        EX_APPLICATION_SPECIFIC = -8,

        // This is special and Java specific; see Parcel.java.
        EX_HAS_REPLY_HEADER = -128,
        // This is special, and indicates to C++ binder proxies that the
        // transaction has failed at a low level.
        EX_TRANSACTION_FAILED = -129,
    };

    // A more readable alias for the default constructor.
    static Status ok();
    // Allow authors to explicitly pick whether their integer is a status_t or
    // exception code.
    static Status fromExceptionCode(int32_t exceptionCode);
    static Status fromExceptionCode(int32_t exceptionCode,
                                    const String8& message);
    static Status fromApplicationError(int32_t applicationErrorCode);
    static Status fromApplicationError(int32_t applicationErrorCode,
                                       const String8& message);
    static Status fromStatusT(status_t status);

    Status() = default;
    ~Status() = default;

    // Status objects are copyable and contain just simple data.
    Status(const Status& status) = default;
    Status(Status&& status) = default;
    Status& operator=(const Status& status) = default;

    // Bear in mind that if the client or service is a Java endpoint, this
    // is not the logic which will provide/interpret the data here.
    status_t readFromParcel(const Parcel& parcel);
    status_t writeToParcel(Parcel* parcel) const;

    // Set one of the pre-defined exception types defined above.
    void setException(int32_t ex, const String8& message);
    // Set an application specific exception with error code.
    void setApplicationError(const String8& message, int32_t errorCode);
    // Setting a |status| != OK causes generated code to return |status|
    // from Binder transactions, rather than writing an exception into the
    // reply Parcel.
    void setFromStatusT(status_t status);

    // Get information about an exception.
    int32_t exceptionCode() const  { return mException; }
    const String8& exceptionMessage() const { return mMessage; }
    status_t statusT() const {
        return mException == EX_TRANSACTION_FAILED ? mErrorCode : OK;
    }
    int32_t applicationErrorCode() const {
        return mException == EX_APPLICATION_SPECIFIC ? mErrorCode : 0;
    }

    bool isOk() const { return mException == EX_NONE; }

    // For logging.
    String8 toString8() const;

private:
    Status(int32_t exceptionCode, int32_t errorCode);
    Status(int32_t exceptionCode, int32_t errorCode, const String8& message);

    // If |mException| == EX_TRANSACTION_FAILED, generated code will return
    // |mErrorCode| as the result of the transaction rather than write an
    // exception to the reply parcel.
    //
    // Otherwise, we always write |mException| to the parcel.
    // If |mException| !=  EX_NONE, we write |mMessage| as well.
    // If |mException| == EX_APPLICATION_SPECIFIC we write |mErrorCode| as well.
    int32_t mException = EX_NONE;
    int32_t mErrorCode = 0;
    String8 mMessage;
};  // class Status

}  // namespace binder
}  // namespace android

#endif // ANDROID_BINDER_STATUS_H
