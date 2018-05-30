/*
 * Copyright (C) 2018 The Android Open Source Project
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

#include <binder/ParcelFileDescriptor.h>

#include <fcntl.h>

namespace android {
namespace os {

ParcelFileDescriptor::ParcelFileDescriptor() = default;

ParcelFileDescriptor::ParcelFileDescriptor(int fd) : mFd(fd) {}

ParcelFileDescriptor::~ParcelFileDescriptor() = default;

status_t ParcelFileDescriptor::writeToParcel(Parcel* parcel) const {
    int dupFd = fcntl(mFd.get(), F_DUPFD_CLOEXEC, 0);
    if (dupFd < 0) return -errno;
    status_t err = parcel->writeParcelFileDescriptor(dupFd, true /* takeOwnership */);
    if (err != NO_ERROR) close(dupFd);
    return err;
}

status_t ParcelFileDescriptor::readFromParcel(const Parcel* parcel) {
    int result = parcel->readParcelFileDescriptor();
    if (result < 0) return result;
    int dupFd = fcntl(result, F_DUPFD_CLOEXEC, 0);
    if (dupFd < 0) return -errno;
    mFd.reset(dupFd);
    return NO_ERROR;
}

}  // namespace os
}  // namespace android
