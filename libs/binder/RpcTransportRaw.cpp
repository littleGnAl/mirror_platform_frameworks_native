/*
 * Copyright (C) 2021 The Android Open Source Project
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

#define LOG_TAG "RpcRawTransport"
#include <log/log.h>

#include <poll.h>
#include <stddef.h>

#include <binder/RpcTransportRaw.h>

#include "FdTrigger.h"
#include "RpcState.h"

namespace android {

namespace {

// RpcTransport with TLS disabled.
class RpcTransportRaw : public RpcTransport {
public:
    explicit RpcTransportRaw(android::base::unique_fd socket) : mSocket(std::move(socket)) {}
    status_t peek(void* buf, size_t size, size_t* out_size) override {
        ssize_t ret = TEMP_FAILURE_RETRY(::recv(mSocket.get(), buf, size, MSG_PEEK));
        if (ret < 0) {
            int savedErrno = errno;
            if (savedErrno == EAGAIN || savedErrno == EWOULDBLOCK) {
                return WOULD_BLOCK;
            }

            LOG_RPC_DETAIL("RpcTransport peek(): %s", strerror(savedErrno));
            return -savedErrno;
        }

        *out_size = static_cast<size_t>(ret);
        return OK;
    }

    template <typename SendOrReceive>
    status_t interruptableReadOrWrite(FdTrigger* fdTrigger, iovec* iovs, int niovs,
                                      SendOrReceive sendOrReceiveFun, const char* funName,
                                      int16_t event, const std::function<status_t()>& altPoll) {
        MAYBE_WAIT_IN_FLAKE_MODE;

        if (niovs < 0) {
            return BAD_VALUE;
        }

        // Since we didn't poll, we need to manually check to see if it was triggered. Otherwise, we
        // may never know we should be shutting down.
        if (fdTrigger->isTriggered()) {
            return DEAD_OBJECT;
        }

        // If iovs has one or more empty vectors at the end and
        // we somehow advance past all the preceding vectors and
        // pass some or all of the empty ones to sendmsg/recvmsg,
        // the call will return processSize == 0. In that case
        // we should be returning OK but instead return DEAD_OBJECT.
        // To avoid this problem, we make sure here that the last
        // vector at iovs[niovs - 1] has a non-zero length.
        while (niovs > 0 && iovs[niovs - 1].iov_len == 0) {
            niovs--;
        }
        if (niovs == 0) {
            // The vectors are all empty, so we have nothing to send.
            return OK;
        }

        bool havePolled = false;
        while (true) {
            ssize_t processSize = sendOrReceiveFun(iovs, niovs);
            if (processSize < 0) {
                int savedErrno = errno;

                // Still return the error on later passes, since it would expose
                // a problem with polling
                if (havePolled || (savedErrno != EAGAIN && savedErrno != EWOULDBLOCK)) {
                    LOG_RPC_DETAIL("RpcTransport %s(): %s", funName, strerror(savedErrno));
                    return -savedErrno;
                }
            } else if (processSize == 0) {
                return DEAD_OBJECT;
            } else {
                while (processSize > 0 && niovs > 0) {
                    auto& iov = iovs[0];
                    if (static_cast<size_t>(processSize) < iov.iov_len) {
                        // Advance the base of the current iovec
                        iov.iov_base = reinterpret_cast<char*>(iov.iov_base) + processSize;
                        iov.iov_len -= processSize;
                        break;
                    }

                    // The current iovec was fully written
                    processSize -= iov.iov_len;
                    iovs++;
                    niovs--;
                }
                if (niovs == 0) {
                    LOG_ALWAYS_FATAL_IF(processSize > 0,
                                        "Reached the end of iovecs "
                                        "with %zd bytes remaining",
                                        processSize);
                    return OK;
                }
            }

            if (altPoll) {
                if (status_t status = altPoll(); status != OK) return status;
                if (fdTrigger->isTriggered()) {
                    return DEAD_OBJECT;
                }
            } else {
                if (status_t status = fdTrigger->triggerablePoll(mSocket.get(), event);
                    status != OK)
                    return status;
                if (!havePolled) havePolled = true;
            }
        }
    }

    status_t interruptableWriteFully(FdTrigger* fdTrigger, iovec* iovs, int niovs,
                                     const std::function<status_t()>& altPoll) override {
        ALOGE("FMAYLE: interruptableWriteFully");
        auto send = [&](iovec* iovs, int niovs) -> status_t {
            if (!mFdsPendingWrite.empty()) {
                std::vector<int> fd_buf;
                fd_buf.reserve(mFdsPendingWrite.size());
                for (const auto& fd : mFdsPendingWrite) {
                    fd_buf.push_back(fd.get());
                }
                const size_t fd_buf_size = sizeof(int) * fd_buf.size();

                mFdsPendingWrite.clear();

                // The buffer needs to be aligned properly for `cmsghdr`, which
                // the C++ allocator does by default as long as the following
                // static assert passes.
                static_assert(alignof(cmsghdr) <= alignof(max_align_t));
                std::vector<char> msg_control_buf;
                msg_control_buf.resize(CMSG_SPACE(fd_buf_size), 0);

                msghdr msg{
                        .msg_iov = iovs,
                        .msg_iovlen = static_cast<decltype(msg.msg_iovlen)>(niovs),
                        .msg_control = msg_control_buf.data(),
                        .msg_controllen = msg_control_buf.size(),
                };

                cmsghdr* cmsg = CMSG_FIRSTHDR(&msg);
                cmsg->cmsg_level = SOL_SOCKET;
                cmsg->cmsg_type = SCM_RIGHTS;
                cmsg->cmsg_len = CMSG_LEN(fd_buf_size);
                memcpy(CMSG_DATA(cmsg), fd_buf.data(), fd_buf_size);

                return TEMP_FAILURE_RETRY(sendmsg(mSocket.get(), &msg, MSG_NOSIGNAL));
            }

            msghdr msg{
                    .msg_iov = iovs,
                    // posix uses int, glibc uses size_t.  niovs is a
                    // non-negative int and can be cast to either.
                    .msg_iovlen = static_cast<decltype(msg.msg_iovlen)>(niovs),
            };
            return TEMP_FAILURE_RETRY(sendmsg(mSocket.get(), &msg, MSG_NOSIGNAL));
        };
        return interruptableReadOrWrite(fdTrigger, iovs, niovs, send, "sendmsg", POLLOUT, altPoll);
    }

    status_t interruptableReadFully(FdTrigger* fdTrigger, iovec* iovs, int niovs,
                                    const std::function<status_t()>& altPoll) override {
        ALOGE("FMAYLE: interruptableReadFully");
        auto recv = [&](iovec* iovs, int niovs) -> status_t {
            // TODO: Check socket type.

            static_assert(alignof(cmsghdr) <= alignof(max_align_t));
            std::vector<char> msg_control_buf;
            // TODO: Move max FDs to constant.
            msg_control_buf.resize(CMSG_SPACE(sizeof(int) * 128), 0);

            msghdr msg{
                    .msg_iov = iovs,
                    // posix uses int, glibc uses size_t.  niovs is a
                    // non-negative int and can be cast to either.
                    .msg_iovlen = static_cast<decltype(msg.msg_iovlen)>(niovs),
                    .msg_control = msg_control_buf.data(),
                    .msg_controllen = msg_control_buf.size(),
            };
            ssize_t processSize = TEMP_FAILURE_RETRY(recvmsg(mSocket.get(), &msg, MSG_NOSIGNAL));

            for (cmsghdr* cmsg = CMSG_FIRSTHDR(&msg); cmsg != nullptr;
                 cmsg = CMSG_NXTHDR(&msg, cmsg)) {
                if (cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
                    // NOTE: cmsg(3) explicitly asks application devs to memcpy the data before
                    // interpreting it to ensure memory alignment.
                    size_t num_fds = cmsg->cmsg_len / sizeof(int);
                    // TODO: Just stack allocate the array here and above since
                    // there is a fixed max.
                    std::unique_ptr<int[]> fds(new int[num_fds]);
                    memcpy(fds.get(), CMSG_DATA(cmsg), cmsg->cmsg_len);
                    for (size_t i = 0; i < num_fds; i++) {
                        // cmsg_len includes padding, so we need to ignore FDs with value 0.
                        if (fds[i] != 0) {
                            mFdsPendingRead.emplace_back(fds[i]);
                        }
                    }
                    break;
                }
            }

            return processSize;
        };
        return interruptableReadOrWrite(fdTrigger, iovs, niovs, recv, "recvmsg", POLLIN, altPoll);
    }

    status_t queueAncillarydata(const std::vector<base::borrowed_fd>& fds) override {
        ALOGE("FMAYLE: queuing %zu FDs", fds.size());
        // TODO: Check socket type.
        mFdsPendingWrite.insert(mFdsPendingWrite.end(), fds.begin(), fds.end());
        return OK;
    }
    status_t consumePendingAncillarydata(std::vector<base::unique_fd>* fds) override {
        ALOGE("FMAYLE: consuming %zu FDs", mFdsPendingRead.size());
        // TODO: Check socket type.
        for (auto& fd : mFdsPendingRead) {
            fds->emplace_back(std::move(fd));
        }
        mFdsPendingRead.clear();
        return OK;
    }

private:
    base::unique_fd mSocket;
    std::vector<base::borrowed_fd> mFdsPendingWrite;
    std::vector<base::unique_fd> mFdsPendingRead;
};

// RpcTransportCtx with TLS disabled.
class RpcTransportCtxRaw : public RpcTransportCtx {
public:
    std::unique_ptr<RpcTransport> newTransport(android::base::unique_fd fd, FdTrigger*) const {
        return std::make_unique<RpcTransportRaw>(std::move(fd));
    }
    std::vector<uint8_t> getCertificate(RpcCertificateFormat) const override { return {}; }
};

} // namespace

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryRaw::newServerCtx() const {
    return std::make_unique<RpcTransportCtxRaw>();
}

std::unique_ptr<RpcTransportCtx> RpcTransportCtxFactoryRaw::newClientCtx() const {
    return std::make_unique<RpcTransportCtxRaw>();
}

const char* RpcTransportCtxFactoryRaw::toCString() const {
    return "raw";
}

std::unique_ptr<RpcTransportCtxFactory> RpcTransportCtxFactoryRaw::make() {
    return std::unique_ptr<RpcTransportCtxFactoryRaw>(new RpcTransportCtxFactoryRaw());
}

} // namespace android
