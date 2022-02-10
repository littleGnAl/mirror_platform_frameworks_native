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

#include "EntryList.h"

#include <memory>
#include <stdio.h>
#include <vector>

#include "BugreportEntries.h"
#include "DumpPool.h"

namespace android::os::dumpstate {

RunnableEntryList::RunnableEntryList(EntryList entries) : entries_(std::move(entries)) {}

void RunnableEntryList::push_back(std::unique_ptr<BugreportEntry> new_entry) {
    entries_.push_back(std::move(new_entry));
}

void RunnableEntryList::ScheduleOnDumpPool(DumpPool* dump_pool) {
    futures_.reserve(entries_.size());
    for (auto& entry : entries_) {
        // TODO(cmtm): use our own duration reporter
        futures_.push_back(dump_pool->enqueueTask(entry->GetTitle(), [&entry] () { entry->Run(); }));
    }
}

void RunnableEntryList::RunAllSingleThreaded(FILE* file) {
    for (auto& entry : entries_) {
        entry->Run();
        entry->WriteToFlatFile(file);
        // Save some memory
        entry.reset();
    }
    entries_.clear();
    entries_.shrink_to_fit();
}

void RunnableEntryList::WaitAndWriteToFile(FILE* file) {
    // TODO(cmtm): we should do the consent check here
    for (int i = 0; i < entries_.size(); i++) {
        // TODO(cmtm): maybe handle errors?
        futures_[i].get();
        entries_[i]->WriteToFlatFile(file);
    }
    futures_.clear();
    futures_.shrink_to_fit();
    entries_.clear();
    entries_.shrink_to_fit();
}


}  // namespace android::os::dumpstate
