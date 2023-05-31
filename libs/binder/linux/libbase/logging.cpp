/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include "android-base/logging.h"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <utility>

#include <android-base/macros.h>
#include <android-base/strings.h>

namespace android {
namespace base {

static const char* GetFileBasename(const char* file) {
    const char* last_slash = std::strrchr(file, '/');
    return last_slash ? last_slash + 1 : file;
}

void DefaultAborter(const char* abort_message) {
    std::fprintf(stderr, "aborting: %s\n", abort_message);
    std::abort();
}

void InitLogging(char* /*argv*/[], LogFunction&& /*logger*/, AbortFunction&& /*aborter*/) {
    // Nothing to do.
}

void StderrLogger(LogId, LogSeverity /*severity*/, const char* /*tag*/, const char* /*file*/,
                  unsigned int /*line*/, const char* /*message*/) {
    // Nothing to do.
}

// This indirection greatly reduces the stack impact of having lots of
// checks/logging in a function.
class LogMessageData {
public:
    LogMessageData(const char* file, unsigned int line, LogSeverity severity, const char* tag,
                   int error)
          : file_(GetFileBasename(file)),
            line_number_(line),
            severity_(severity),
            tag_(tag),
            error_(error) {}

    const char* GetFile() const { return file_; }

    unsigned int GetLineNumber() const { return line_number_; }

    LogSeverity GetSeverity() const { return severity_; }

    const char* GetTag() const { return tag_; }

    int GetError() const { return error_; }

    std::ostream& GetBuffer() { return buffer_; }

    std::string ToString() const { return buffer_.str(); }

private:
    std::ostringstream buffer_;
    const char* const file_;
    const unsigned int line_number_;
    const LogSeverity severity_;
    const char* const tag_;
    const int error_;

    DISALLOW_COPY_AND_ASSIGN(LogMessageData);
};

LogMessage::LogMessage(const char* file, unsigned int line, LogId, LogSeverity severity,
                       const char* tag, int error)
      : LogMessage(file, line, severity, tag, error) {}

LogMessage::LogMessage(const char* file, unsigned int line, LogSeverity severity, const char* tag,
                       int error)
      : data_(new LogMessageData(file, line, severity, tag, error)) {}

LogMessage::~LogMessage() {
    // Check severity again. This is duplicate work wrt/ LOG macros, but not LOG_STREAM.
    if (!WOULD_LOG(data_->GetSeverity())) {
        return;
    }

    // Finish constructing the message.
    if (data_->GetError() != -1) {
        data_->GetBuffer() << ": " << strerror(data_->GetError());
    }
    std::string msg(data_->ToString());

    LogLine(data_->GetFile(), data_->GetLineNumber(), data_->GetSeverity(), data_->GetTag(),
            msg.c_str());

    // Abort if necessary.
    if (data_->GetSeverity() == FATAL) {
        DefaultAborter(msg.c_str());
    }
}

std::ostream& LogMessage::stream() {
    return data_->GetBuffer();
}

void LogMessage::LogLine(const char* /* file */, unsigned int /* line */,
                         LogSeverity /* severity */, const char* tag, const char* message) {
    const char* tag_or_unknown = tag ? tag : "<unknown>";
    const char* newline;
    while ((newline = std::strchr(message, '\n')) != nullptr) {
        std::fprintf(stderr, "%s: ", tag_or_unknown);
        std::fwrite(message, 1, newline - message, stderr);
        std::fputc('\n', stderr);
        message = newline + 1;
    }
    std::fprintf(stderr, "%s: %s", tag_or_unknown, message);
}

bool ShouldLog(LogSeverity /*severity*/, const char* /*tag*/) {
    // Simply mocking.
    return true;
}

} // namespace base
} // namespace android
