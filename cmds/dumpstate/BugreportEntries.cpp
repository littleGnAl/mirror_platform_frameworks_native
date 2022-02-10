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

#define LOG_TAG "dumpstate"

#include "BugreportEntries.h"

#include <stdio.h>
#include <string_view>
#include <string>

#include <fmt/core.h>
#include <sys/mman.h>
#include <sys/sendfile.h>
#include <unistd.h>

#include "DumpstateUtil.h"


namespace android::os::dumpstate {

namespace {

int GetCleanedFd(FILE* stream) {
    // Streams need to be cleaned (by fflushing them) before doing I/O with the underlying fd.
    fflush(stream);
    return fileno(stream);
}

/*

std::string SimpleHeader(std::string title) {
    return fmt::format("------ {} ------\n", title);
}
*/


}  // namespace

BugreportEntry::BugreportEntry(std::string title) : title_(std::move(title)) {}

const std::string& BugreportEntry::GetTitle() { return title_; }

void BugreportEntryWithBuffer::WriteToFlatFile(FILE* flat_file) {
    // TODO(cmtm): might be faster with writev directly to the fd.
    for (auto& chunk : bufs_) {
        fwrite(chunk.data(), chunk.size(), 1, flat_file);
    }
}

CommandOutputEntry::CommandOutputEntry(std::string title, std::vector<std::string> full_command,
                                       CommandOptions options)
        : BugreportEntryWithBuffer(std::move(title)), full_command_(std::move(full_command)), options_(std::move(options)) {}

int CommandOutputEntry::Run() {
    android::base::unique_fd fd {memfd_create("bugreport_entry_tmp_file", MFD_CLOEXEC)};
    // TODO(cmtm): handle error of fd not being creatable

    // TODO(cmtm): move RunCommandToFd to here and fix it up
    int result = RunCommandToFd(fd.get(), title_, full_command_, options_);

    // get length of file by looking at current file offset, which will be at the end.
    off_t file_length = lseek(fd.get(), 0, SEEK_CUR);
    // rewind file position to beginning of file
    lseek(fd.get(), 0, SEEK_SET);

    std::string buf;
    buf.resize(file_length);
    read(fd.get(), buf.data(), file_length);
    bufs_.push_back(std::move(buf));
    return result;
}

std::unique_ptr<CommandOutputEntry> MakeCommandOutputEntry(std::string title,
            std::vector<std::string> full_command, CommandOptions options) {
    return std::make_unique<CommandOutputEntry>(std::move(title), std::move(full_command), std::move(options));
}

std::unique_ptr<CommandOutputEntry> MakeDumpsysEntry(std::string title,
        std::vector<std::string> dumpsys_args, CommandOptions options) {
    std::vector<std::string> full_command = {"/system/bin/dumpsys", "-T", std::to_string(options.TimeoutInMs())};
    // TODO(cmtm): move strings properly here
    full_command.insert(full_command.end(), dumpsys_args.begin(), dumpsys_args.end());
    return std::make_unique<CommandOutputEntry>(std::move(title), std::move(full_command), std::move(options));
}


FunctionEntry::FunctionEntry(std::string title, Func func)
        : BugreportEntryWithBuffer(std::move(title)), func_(std::move(func)) {}

int FunctionEntry::Run() {
    return func_(&bufs_);
}

std::unique_ptr<FunctionEntry> MakeFunctionEntry(std::string title, FunctionEntry::Func func) {
    return std::make_unique<FunctionEntry>(std::move(title), std::move(func));
}


FileEntry::FileEntry(std::string title, std::string path) : BugreportEntry(std::move(title)), path_(std::move(path)) {}

// Nothing to do here.
int FileEntry::Run() { return 0; }

void FileEntry::WriteToFlatFile(FILE* flat_file) {
    // TODO(cmtm): move move here and fix it up. Use sendfile
    DumpFileToFd(GetCleanedFd(flat_file), title_, path_);
}

std::unique_ptr<FileEntry> MakeFileEntry(std::string title, std::string path) {
    return std::make_unique<FileEntry>(std::move(title), std::move(path));
}


NoOutputEntry::NoOutputEntry(std::string title, std::function<void()> func) : BugreportEntry(std::move(title)), func_(std::move(func)) {}

int NoOutputEntry::Run() { func_(); return 0; }

// Nothing to do here.
void NoOutputEntry::WriteToFlatFile([[maybe_unused]] FILE* flat_file) {};

std::unique_ptr<NoOutputEntry> MakeNoOutputEntry(std::string title, std::function<void()> func) {
    return std::make_unique<NoOutputEntry>(std::move(title), std::move(func));
}


LegacyStdoutEntry::LegacyStdoutEntry(std::string title, std::function<void()> func)
        : BugreportEntry(std::move(title)), func_(std::move(func)) {}

// Nothing to do here.
int LegacyStdoutEntry::Run() { return 0; }

void LegacyStdoutEntry::WriteToFlatFile(FILE* flat_file) {
    // save existing stdout
    int stdout_fd = GetCleanedFd(stdout);
    int saved_stdout = fcntl(stdout_fd, F_DUPFD_CLOEXEC);

    // now point stdout to flat_file. Don't use CLOEXEC incase the legacy function forks.
    int ret = dup2(GetCleanedFd(flat_file), saved_stdout);

    // call the function; it will print its result to stdout
    func_();

    // restore stdout
    dup2(saved_stdout, stdout_fd);
}

std::unique_ptr<LegacyStdoutEntry> MakeLegacyStdoutEntry(std::string title, std::function<void()> func) {
    return std::make_unique<LegacyStdoutEntry>(std::move(title), std::move(func));
}


LegacyTmpfileEntry::LegacyTmpfileEntry(std::string title, std::function<void(int)> func)
        : BugreportEntryWithBuffer(std::move(title)), func_(std::move(func)) {}

int LegacyTmpfileEntry::Run() {
    // TODO(cmtm): factor this out, it's similar to CommandOutputEntry now.
    android::base::unique_fd fd {memfd_create("bugreport_entry_tmp_file", MFD_CLOEXEC)};
    // TODO(cmtm): handle error of fd not being creatable

    func_(fd.get());

    // get length of file by looking at current file offset, which will be at the end.
    off_t file_length = lseek(fd.get(), 0, SEEK_CUR);
    // rewind file position to beginning of file
    lseek(fd.get(), 0, SEEK_SET);

    std::string buf;
    buf.resize(file_length);
    read(fd.get(), buf.data(), file_length);
    bufs_.push_back(std::move(buf));
    return 0;
}

std::unique_ptr<LegacyTmpfileEntry> MakeLegacyTmpfileEntry(std::string title, std::function<void(int)> func) {
    return std::make_unique<LegacyTmpfileEntry>(std::move(title), std::move(func));
}


TrivialStringEntry::TrivialStringEntry(std::string title, std::string text) : BugreportEntry(std::move(title)), text_(std::move(text)) {}

// Nothing to do here.
int TrivialStringEntry::Run() { return 0; }

void TrivialStringEntry::WriteToFlatFile(FILE* flat_file) {
    // TODO(cmtm): catch errors?
    fwrite(text_.data(), text_.length(), 1, flat_file);
}

std::unique_ptr<TrivialStringEntry> MakeTrivialStringEntry(std::string title, std::string text) {
    return std::make_unique<TrivialStringEntry>(std::move(title), std::move(text));
}

std::unique_ptr<TrivialStringEntry> MakeBigSectionHeader(std::string title) {
    return MakeTrivialStringEntry(title, fmt::format(
        "========================================================\n"
        "== {}\n"
        "========================================================\n", title));
}

}  // namespace android::os::dumpstate
