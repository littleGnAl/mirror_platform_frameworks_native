/*
 * Copyright (C) 2022 The Android Open Source Project
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
#pragma once

#include <android-base/unique_fd.h>
#include <utils/Errors.h>

#include <sys/socket.h>

namespace android {

static inline status_t SendFdOverUnixSocket(base::borrowed_fd transportFd, base::unique_fd sendFd) {
    int fdBuffer = sendFd.get();

    // Need to transfer *something* with the control message.
    iovec iov = {.iov_base = &fdBuffer, .iov_len = sizeof(fdBuffer)};

    alignas(cmsghdr) char msgControlBuf[CMSG_SPACE(sizeof(fdBuffer))] = {};
    msghdr msgHeader = {
            .msg_name = nullptr,
            .msg_namelen = 0,
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = msgControlBuf,
            .msg_controllen = sizeof(msgControlBuf),
    };
    cmsghdr* msgControlHeader = CMSG_FIRSTHDR(&msgHeader);
    *msgControlHeader = {
            .cmsg_len = CMSG_LEN(sizeof(fdBuffer)),
            .cmsg_level = SOL_SOCKET,
            .cmsg_type = SCM_RIGHTS,
    };
    memcpy(CMSG_DATA(msgControlHeader), &fdBuffer, sizeof(fdBuffer));

    if (TEMP_FAILURE_RETRY(sendmsg(transportFd.get(), &msgHeader, 0)) < 0) {
        return -errno;
    }
    return OK;
}

static inline status_t ReceiveFdOverUnixSocket(base::borrowed_fd transportFd,
                                               base::unique_fd* outFd) {
    int fdBuffer;

    // Need to receive *something* with the control message.
    iovec iov = {.iov_base = &fdBuffer, .iov_len = sizeof(fdBuffer)};

    alignas(cmsghdr) char msgControlBuf[CMSG_SPACE(sizeof(fdBuffer))];
    msghdr msgHeader = {
            .msg_name = nullptr,
            .msg_namelen = 0,
            .msg_iov = &iov,
            .msg_iovlen = 1,
            .msg_control = msgControlBuf,
            .msg_controllen = sizeof(msgControlBuf),
    };

    if (TEMP_FAILURE_RETRY(recvmsg(transportFd.get(), &msgHeader, 0)) < 0) {
        return -errno;
    }

    cmsghdr* msgControlHeader = CMSG_FIRSTHDR(&msgHeader);
    if (msgControlHeader == nullptr || msgControlHeader->cmsg_len != CMSG_LEN(sizeof(fdBuffer)) ||
        msgControlHeader->cmsg_level != SOL_SOCKET || msgControlHeader->cmsg_type != SCM_RIGHTS) {
        return -EINVAL;
    }

    memcpy(&fdBuffer, CMSG_DATA(msgControlHeader), sizeof(fdBuffer));
    *outFd = base::unique_fd(fdBuffer);
    return OK;
}

} // namespace android
