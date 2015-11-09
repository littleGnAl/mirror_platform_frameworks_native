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

#include <binder/Error.h>

using android::OK;
using android::Parcel;
using android::String8;

namespace android {
namespace binder {

status_t Error::readFromParcel(const Parcel& parcel) {
    int32_t exception_value = 0;
    status_t status = parcel.readInt32(&exception_value);
    if (status != OK) {
        setFromStatusT(status);
        return status;
    }

    // This is super ugly, but necessary to check the validity of the
    // exception code we read.
    switch (exception_value) {
        case int32_t(Exception::EX_NONE):
            exception_ = Exception::EX_NONE;
            break;
        case int32_t(Exception::EX_SECURITY):
            exception_ = Exception::EX_SECURITY;
            break;
        case int32_t(Exception::EX_BAD_PARCELABLE):
            exception_ = Exception::EX_BAD_PARCELABLE;
            break;
        case int32_t(Exception::EX_ILLEGAL_ARGUMENT):
            exception_ = Exception::EX_ILLEGAL_ARGUMENT;
            break;
        case int32_t(Exception::EX_NULL_POINTER):
            exception_ = Exception::EX_NULL_POINTER;
            break;
        case int32_t(Exception::EX_ILLEGAL_STATE):
            exception_ = Exception::EX_ILLEGAL_STATE;
            break;
        case int32_t(Exception::EX_NETWORK_MAIN_THREAD):
            exception_ = Exception::EX_NETWORK_MAIN_THREAD;
            break;
        case int32_t(Exception::EX_UNSUPPORTED_OPERATION):
            exception_ = Exception::EX_UNSUPPORTED_OPERATION;
            break;
        case int32_t(Exception::EX_HAS_REPLY_HEADER):
            exception_ = Exception::EX_HAS_REPLY_HEADER;
            break;
        // We should never read that the transaction failed from
        // a Parcel, since the parcel is proof that the transaction
        // succeeded from a Binder driver perspective.
        case int32_t(Exception::EX_TRANSACTION_FAILED):
        default:
            status = FAILED_TRANSACTION;
            setFromStatusT(status);
            return status;
    }

    // Skip over fat response headers.  Not used (or propagated) in native code.
    if (exception_ == Exception::EX_HAS_REPLY_HEADER) {
        // Note that the header size includes the 4 byte size field.
        const int32_t header_start = parcel.dataPosition();
        int32_t header_size;
        status = parcel.readInt32(&header_size);
        if (status != OK) {
            setFromStatusT(status);
            return status;
        }
        parcel.setDataPosition(header_start + header_size);
        // And fat response headers are currently only used when there are no
        // exceptions, so act like there was no error.
        exception_ = Exception::EX_NONE;
    }

    if (exception_ == Exception::EX_NONE) {
        return status;
    }

    // The remote threw an exception.  Get the message back.
    message_ = String8(parcel.readString16());

    return status;
}

status_t Error::writeToParcel(Parcel* parcel) const {
    status_t status = parcel->writeInt32(int32_t(exception_));
    if (status != OK || exception_ == Exception::EX_NONE) {
        return status;
    }
    status = parcel->writeString16(String16(message_));
    return status;
}

void Error::setFromStatusT(status_t status) {
    switch (status) {
        case NO_ERROR:
            exception_ = Exception::EX_NONE;
            message_.clear();
            break;
        default:
            exception_ = Exception::EX_TRANSACTION_FAILED;
            message_.setTo("Transaction failed");
            break;
    }
}

void Error::setException(Exception ex, const String8& message) {
    exception_ = ex;
    message_.setTo(message);
}

void Error::ensureException() {
    if (!isOk()) {
        return;
    }
    // If we get here, the service has really messed up.  It's said "this IPC
    // failed," but failed to provide an exception.  Fill in some reasonable
    // default.
    setException(Exception::EX_UNSUPPORTED_OPERATION,
                 String8("Service did not specify an exception."));
}

void Error::getException(Exception* returned_exception,
                         String8* returned_message) const {
    if (returned_exception) {
        *returned_exception = exception_;
    }
    if (returned_message) {
        returned_message->setTo(message_);
    }
}

android::String8 Error::toString8() const {
    android::String8 ret;
    if (exception_ == Exception::EX_NONE) {
        ret.append("No error");
    } else {
        ret.appendFormat("Error(%d): '", int32_t(exception_));
        ret.append(String8(message_));
        ret.append("'");
    }
  return ret;
}

}  // namespace binder
}  // namespace android
