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

#ifndef FRAMEWORKS_NATIVE_CMDS_DUMPSTATE_BUGREPORTENTRIES_H_
#define FRAMEWORKS_NATIVE_CMDS_DUMPSTATE_BUGREPORTENTRIES_H_

#include <memory>
#include <stdio.h>
#include <string>
#include <vector>


#include <android-base/unique_fd.h>

// TODO(cmtm): remove this circular dependency after cleaning up dumpstate
#include "dumpstate.h"

#include "DumpstateUtil.h"

namespace android::os::dumpstate {

class BugreportEntry {
  public:
    BugreportEntry(std::string title);

    virtual ~BugreportEntry() = default;

    virtual int Run() = 0;

    virtual void WriteToFlatFile(FILE* flat_file) = 0;

    const std::string& GetTitle();

  protected:
    std::string title_;
};

class BugreportEntryWithBuffer : public BugreportEntry {
  public:
    using BugreportEntry::BugreportEntry;

    int Run() = 0;

    void WriteToFlatFile(FILE* flat_file) final;

  protected:
    // This is a vector of buffers in case it's more efficient to build it up in chunks.
    std::vector<std::string> bufs_;
};

class CommandOutputEntry : public BugreportEntryWithBuffer {
  public:
    CommandOutputEntry(std::string title, std::vector<std::string> full_command,
                       CommandOptions options = CommandOptions::DEFAULT);

    int Run() override;

  private:
    std::vector<std::string> full_command_;
    CommandOptions options_;
};
// TODO(cmtm): why doesn't the below work
// const auto& MakeCommandOutputEntry = std::make_unique<CommandOutputEntry>;
std::unique_ptr<CommandOutputEntry> MakeCommandOutputEntry(std::string title,
            std::vector<std::string> full_command, CommandOptions options = CommandOptions::DEFAULT);

std::unique_ptr<CommandOutputEntry> MakeDumpsysEntry(std::string title,
        std::vector<std::string> dumpsys_args, CommandOptions options = Dumpstate::DEFAULT_DUMPSYS);

class FunctionEntry : public BugreportEntryWithBuffer {
  public:
    using Func = std::function<int(std::vector<std::string>*)>;

    FunctionEntry(std::string title, Func func);

    int Run() override;

  private:
    std::function<int(std::vector<std::string>*)> func_;
};
std::unique_ptr<FunctionEntry> MakeFunctionEntry(std::string title, FunctionEntry::Func func);

class FileEntry : public BugreportEntry {
  public:
    FileEntry(std::string title, std::string path);

    int Run() override;

    void WriteToFlatFile(FILE* flat_file) override;

  private:
    std::string path_;
};
std::unique_ptr<FileEntry> MakeFileEntry(std::string title, std::string path);

// This type of entry doesn't have any output to create. It's used to represent work that doesn't
// directly result it output to the flat bugreport file.
class NoOutputEntry : public BugreportEntry {
  public:
    NoOutputEntry(std::string title, std::function<void()> func);

    int Run() override;

    void WriteToFlatFile(FILE* flat_file) override;

  private:
    std::function<void()> func_;
};
std::unique_ptr<NoOutputEntry> MakeNoOutputEntry(std::string title, std::function<void()> func);

// Bugreport used to consist of a bunch of code that just wrote to STDOUT. The functions that
// haven't been converted to the newer BugreportEntries style can be represented by LegacyEntries.
// Note that these can't benefit from any paralellism, and so are run entirely in the
// `WriteToFlatFile()` function, so that they will be run serially.
class LegacyStdoutEntry : public BugreportEntry {
  public:
    LegacyStdoutEntry(std::string title, std::function<void()> func);

    int Run() override;

    void WriteToFlatFile(FILE* flat_file) override;

  private:
    std::function<void()> func_;
};
std::unique_ptr<LegacyStdoutEntry> MakeLegacyStdoutEntry(std::string title, std::function<void()> func);

class LegacyTmpfileEntry : public BugreportEntryWithBuffer {
  public:
    LegacyTmpfileEntry(std::string title, std::function<void(int)> func);

    int Run() override;

  private:
    std::function<void(int)> func_;
};
std::unique_ptr<LegacyTmpfileEntry> MakeLegacyTmpfileEntry(std::string title, std::function<void(int)> func);

class TrivialStringEntry : public BugreportEntry {
  public:
    TrivialStringEntry(std::string title, std::string text);

    int Run() override;

    void WriteToFlatFile(FILE* flat_file) override;

  private:
    std::string text_;
};
std::unique_ptr<TrivialStringEntry> MakeTrivialStringEntry(std::string title, std::string text);

std::unique_ptr<TrivialStringEntry> MakeBigSectionHeader(std::string title);


}  // namespace android::os::dumpstate

#endif  // FRAMEWORKS_NATIVE_CMDS_DUMPSTATE_BUGREPORTENTRIES_H_
