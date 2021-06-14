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

std::variant<Pipe, int /* errno */> Pipe::make() {
    Pipe ret;
    if (!android::base::Pipe(&ret.mRead, &ret.mWrite)) return errno;
    return ret;
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

ExecuteResult execute(std::vector<std::string> argStringVec,
                      const std::function<bool(const CommandResult&)>& end) {
    // turn vector<string> into null-terminated char* vector.
    std::vector<char*> argv;
    argv.reserve(argStringVec.size());
    for (auto& arg : argStringVec) argv.push_back(arg.data());
    argv.push_back(nullptr);

    CommandResult ret;
    {
        auto outPipe = Pipe::make();
        if (std::holds_alternative<int>(outPipe))
            return ExecuteError(std::get<int>(outPipe), "pipe() for outPipe");
        ret.outPipe = std::move(std::get<Pipe>(outPipe));
        auto errPipe = Pipe::make();
        if (std::holds_alternative<int>(errPipe))
            return ExecuteError(std::get<int>(errPipe), "pipe() for errPipe");
        ret.errPipe = std::move(std::get<Pipe>(errPipe));
    }

    int pid = fork();
    if (pid == -1) return ExecuteError("fork()");
    if (pid == 0) {
        // child
        ret.outPipe->readEnd().reset();
        ret.errPipe->readEnd().reset();

        int res = TEMP_FAILURE_RETRY(dup2(ret.outPipe->writeEnd().get(), STDOUT_FILENO));
        LOG_ALWAYS_FATAL_IF(-1 == res, "dup2(outPipe): %s", strerror(errno));
        ret.outPipe->writeEnd().reset();

        res = TEMP_FAILURE_RETRY(dup2(ret.errPipe->writeEnd().get(), STDERR_FILENO));
        LOG_ALWAYS_FATAL_IF(-1 == res, "dup2(errPipe): %s", strerror(errno));
        ret.errPipe->writeEnd().reset();

        execvp(argv[0], argv.data());
        LOG_ALWAYS_FATAL("execvp() returns");
    }
    // parent
    ret.outPipe->writeEnd().reset();
    ret.errPipe->writeEnd().reset();

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
        if (ret.outPipe->readEnd().ok()) {
            FD_SET(ret.outPipe->readEnd().get(), &readfds);
            nfds = std::max(nfds, ret.outPipe->readEnd().get());
        }
        if (ret.errPipe->readEnd().ok()) {
            FD_SET(ret.errPipe->readEnd().get(), &readfds);
            nfds = std::max(nfds, ret.errPipe->readEnd().get());
        }
        nfds += 1;
        int selectRet = select(nfds, &readfds, nullptr, nullptr, nullptr);
        if (selectRet == -1) return ExecuteError("select()");
        LOG_ALWAYS_FATAL_IF(selectRet == 0, "select() with null timeout should never return 0");

        if (ret.outPipe->readEnd().ok() && FD_ISSET(ret.outPipe->readEnd().get(), &readfds)) {
            auto n = appendOnce(ret.outPipe->readEnd(), &ret.stdout);
            if (n == -1) return ExecuteError("read(stdout)");
            if (n == 0) {
                ret.outPipe->readEnd().reset();
            }
        }
        if (ret.errPipe->readEnd().ok() && FD_ISSET(ret.errPipe->readEnd().get(), &readfds)) {
            auto n = appendOnce(ret.errPipe->readEnd(), &ret.stderr);
            if (n == -1) return ExecuteError("read(stderr)");
            if (n == 0) {
                ret.errPipe->readEnd().reset();
            }
        }

        if (!ret.outPipe->readEnd().ok() && !ret.errPipe->readEnd().ok()) {
            while (ret.pid.has_value()) {
                int status;
                auto exitPid = waitpid(pid, &status, 0);
                if (exitPid == -1) return ExecuteError("waitpid(" + std::to_string(pid) + ")");
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
