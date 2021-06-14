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

#include "Utils.h"

#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <sstream>

#include <log/log.h>

namespace android {

void zeroMemory(uint8_t* data, size_t size) {
    memset(data, 0, size);
}

std::ostream& operator<<(std::ostream& os, const ExecuteError& res) {
    return os << strerror(res.code) << (res.message.empty() ? "" : ": ") << res.message;
}

std::string ExecuteError::toString() const {
    std::stringstream ss;
    ss << (*this);
    return ss.str();
}

CommandResult::~CommandResult() {
    if (!pid.has_value()) return;
    if (*pid == 0) {
        ALOGW("%s: PID is unexpectedly 0, won't kill it", __PRETTY_FUNCTION__);
        return;
    }

    ALOGE_IF(kill(*pid, SIGKILL) != 0, "kill(%d): %s", *pid, strerror(errno));

    while (pid.has_value()) {
        int status;
        ALOGI("%s: Waiting for PID %d to exit.", __PRETTY_FUNCTION__, *pid);
        int waitres = waitpid(*pid, &status, 0);
        if (waitres == -1) {
            ALOGE("%s: waitpid(%d): %s", __PRETTY_FUNCTION__, *pid, strerror(errno));
            break;
        }
        if (WIFEXITED(status)) {
            ALOGI("%s: PID %d exited.", __PRETTY_FUNCTION__, *pid);
            pid.reset();
        } else if (WIFSIGNALED(status)) {
            ALOGI("%s: PID %d terminated by signal %d.", __PRETTY_FUNCTION__, *pid,
                  WTERMSIG(status));
            pid.reset();
        } else if (WIFSTOPPED(status)) {
            ALOGW("%s: pid %d stopped", __PRETTY_FUNCTION__, *pid);
        } else if (WIFCONTINUED(status)) {
            ALOGW("%s: pid %d continued", __PRETTY_FUNCTION__, *pid);
        }
    }
}

std::ostream& operator<<(std::ostream& os, const CommandResult& res) {
    if (res.exitCode) os << "code=" << *res.exitCode;
    if (res.signal) os << "signal=" << *res.signal;
    if (res.pid) os << ", pid=" << *res.pid;
    return os << ", stdout=" << res.stdout << ", stderr=" << res.stderr;
}
std::string CommandResult::toString() const {
    std::stringstream ss;
    ss << (*this);
    return ss.str();
}

std::ostream& operator<<(std::ostream& os, const ExecuteResult& res) {
    if (res.has_value())
        return os << res.value();
    else
        return os << res.error();
}

ExecuteResult execute(std::vector<std::string> argStringVec,
                      const std::function<bool(const CommandResult&)>& end) {
    // turn vector<string> into null-terminated char* vector.
    std::vector<char*> argv;
    argv.reserve(argStringVec.size());
    for (auto& arg : argStringVec) argv.push_back(arg.data());
    argv.push_back(nullptr);

    CommandResult ret;
    android::base::unique_fd outWrite;
    if (!android::base::Pipe(&ret.outPipe, &outWrite))
        return android::base::unexpected(ExecuteError(errno, "pipe() for outPipe"));
    android::base::unique_fd errWrite;
    if (!android::base::Pipe(&ret.errPipe, &errWrite))
        return android::base::unexpected(ExecuteError(errno, "pipe() for errPipe"));

    int pid = fork();
    if (pid == -1) return android::base::unexpected(ExecuteError(errno, "fork()"));
    if (pid == 0) {
        // child
        ret.outPipe.reset();
        ret.errPipe.reset();

        int res = TEMP_FAILURE_RETRY(dup2(outWrite.get(), STDOUT_FILENO));
        LOG_ALWAYS_FATAL_IF(-1 == res, "dup2(outPipe): %s", strerror(errno));
        outWrite.reset();

        res = TEMP_FAILURE_RETRY(dup2(errWrite.get(), STDERR_FILENO));
        LOG_ALWAYS_FATAL_IF(-1 == res, "dup2(errPipe): %s", strerror(errno));
        errWrite.reset();

        execvp(argv[0], argv.data());
        LOG_ALWAYS_FATAL("execvp() returns");
    }
    // parent
    outWrite.reset();
    errWrite.reset();

    auto appendOnce = [](android::base::borrowed_fd fd, std::string* s) -> ssize_t {
        char buf[1024];
        ssize_t n = TEMP_FAILURE_RETRY(read(fd.get(), buf, sizeof(buf)));
        if (n > 0) {
            *s += std::string_view(buf, n);
        }
        return n;
    };

    ret.pid = pid;
    while (true) {
        int nfds = -1;
        fd_set readfds;
        FD_ZERO(&readfds);
        if (ret.outPipe.ok()) {
            FD_SET(ret.outPipe.get(), &readfds);
            nfds = std::max(nfds, ret.outPipe.get());
        }
        if (ret.errPipe.ok()) {
            FD_SET(ret.errPipe.get(), &readfds);
            nfds = std::max(nfds, ret.errPipe.get());
        }
        nfds += 1;
        int selectRet = select(nfds, &readfds, nullptr, nullptr, nullptr);
        if (selectRet == -1) return android::base::unexpected(ExecuteError(errno, "select()"));
        LOG_ALWAYS_FATAL_IF(selectRet == 0, "select() with null timeout should never return 0");

        if (ret.outPipe.ok() && FD_ISSET(ret.outPipe.get(), &readfds)) {
            auto n = appendOnce(ret.outPipe, &ret.stdout);
            if (n == -1) return android::base::unexpected(ExecuteError(errno, "read(stdout)"));
            if (n == 0) {
                ret.outPipe.reset();
            }
        }
        if (ret.errPipe.ok() && FD_ISSET(ret.errPipe.get(), &readfds)) {
            auto n = appendOnce(ret.errPipe, &ret.stderr);
            if (n == -1) return android::base::unexpected(ExecuteError(errno, "read(stderr)"));
            if (n == 0) {
                ret.errPipe.reset();
            }
        }

        if (!ret.outPipe.ok() && !ret.errPipe.ok()) {
            while (ret.pid.has_value()) {
                int status;
                auto exitPid = waitpid(pid, &status, 0);
                if (exitPid == -1)
                    return android::base::unexpected(
                            ExecuteError(errno, "waitpid(" + std::to_string(pid) + ")"));
                if (exitPid == pid) {
                    if (WIFEXITED(status)) {
                        ret.pid = std::nullopt;
                        ret.exitCode = WEXITSTATUS(status);
                    } else if (WIFSIGNALED(status)) {
                        ret.pid = std::nullopt;
                        ret.signal = WTERMSIG(status);
                    } else if (WIFSTOPPED(status)) {
                        ALOGW("%s: pid %d stopped", __PRETTY_FUNCTION__, *ret.pid);
                    } else if (WIFCONTINUED(status)) {
                        ALOGW("%s: pid %d continued", __PRETTY_FUNCTION__, *ret.pid);
                    }
                }
            }
        }

        if (!ret.pid.has_value() || (end && end(ret))) return ret;
    }
}
} // namespace android
