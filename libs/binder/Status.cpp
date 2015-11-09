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

#include <binder/Status.h>

using android::OK;
using android::Parcel;
using android::String8;

namespace android {
namespace binder {


Status Status::fromExceptionCode(int32_t exception_code) {
  return Status(exception_code, String8(""));
}

Status Status::fromStatusT(status_t status) {
  Status ret;
  ret.setFromStatusT(status);
  return ret;
}

Status Status::Ok() {
  return Status();
}

Status::Status(int32_t exception_code, android::String8 message)
    : exception_(exception_code),
      message_(message) {}

status_t Status::readFromParcel(const Parcel& parcel) {
    status_t status = parcel.readInt32(&exception_);
    if (status != OK) {
        setFromStatusT(status);
        return status;
    }

    // Skip over fat response headers.  Not used (or propagated) in native code.
    if (exception_ == EX_HAS_REPLY_HEADER) {
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
        exception_ = EX_NONE;
    }

    if (exception_ == EX_NONE) {
        return status;
    }

    // The remote threw an exception.  Get the message back.
    message_ = String8(parcel.readString16());

    return status;
}

status_t Status::writeToParcel(Parcel* parcel) const {
    status_t status = parcel->writeInt32(exception_);
    if (status != OK || exception_ == EX_NONE) {
        return status;
    }
    status = parcel->writeString16(String16(message_));
    return status;
}

void Status::setFromStatusT(status_t status) {
    switch (status) {
        case NO_ERROR:
            exception_ = EX_NONE;
            message_.clear();
            break;
        case UNEXPECTED_NULL:
            exception_ = EX_NULL_POINTER;
            message_.setTo("Unexpected null reference in Parcel");
            break;
        default:
            exception_ = EX_TRANSACTION_FAILED;
            message_.setTo("Transaction failed");
            break;
    }
}

void Status::setException(int32_t ex, const String8& message) {
    exception_ = ex;
    message_.setTo(message);
}

void Status::getException(int32_t* returned_exception,
                          String8* returned_message) const {
    if (returned_exception) {
        *returned_exception = exception_;
    }
    if (returned_message) {
        returned_message->setTo(message_);
    }
}

android::String8 Status::toString8() const {
    android::String8 ret;
    if (exception_ == EX_NONE) {
        ret.append("No error");
    } else {
        ret.appendFormat("Status(%d): '", exception_);
        ret.append(String8(message_));
        ret.append("'");
    }
  return ret;
}

}  // namespace binder
}  // namespace android
