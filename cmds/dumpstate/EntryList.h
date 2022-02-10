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

#ifndef FRAMEWORKS_NATIVE_CMDS_DUMPSTATE_ENTRYLIST_H_
#define FRAMEWORKS_NATIVE_CMDS_DUMPSTATE_ENTRYLIST_H_

#include <memory>
#include <stdio.h>
#include <vector>

#include "BugreportEntries.h"
#include "DumpPool.h"

namespace android::os::dumpstate {

using EntryList = std::vector<std::unique_ptr<BugreportEntry>>;

// Helper utility for making EntryLists. `initializer_list`s can't contain move-only types, so we
// use old style c arrays instead and convert them to EntryList.
template<class T>
static EntryList MakeEntryList(T&& entries) {
    EntryList list(std::make_move_iterator(std::begin(entries)),
                   std::make_move_iterator(std::end(entries)));
    return list;
}

template<class T>
void ExtendEntryList(EntryList& entry_list, T&& new_entries) {
    entry_list.insert(entry_list.end(), std::make_move_iterator(std::begin(new_entries)),
                                      std::make_move_iterator(std::end(new_entries)));
}

class RunnableEntryList {
  public:
    RunnableEntryList(EntryList entries = {});



    // This function exists to make it easier to define a bunch of `BugreportEntry`s.
    // `initializer_list`s can't contain move-only types, so we use old style c arrays instead.
    template<class T>
    void Extend(T&& new_entries) {
        entries_.insert(entries_.end(), std::make_move_iterator(std::begin(new_entries)),
                                        std::make_move_iterator(std::end(new_entries)));
    }

    void push_back(std::unique_ptr<BugreportEntry> new_entry);

    void ScheduleOnDumpPool(DumpPool* dump_pool);

    // Run all entries on a single thread (the current one) and block.
    void RunAllSingleThreaded(FILE* file);

    void WaitAndWriteToFile(FILE* file);

  private:
    // TODO(cmtm): change DumpPool to no longer return strings
    std::vector<std::future<void>> futures_;
    EntryList entries_;
};

}  // namespace android::os::dumpstate

#endif  // FRAMEWORKS_NATIVE_CMDS_DUMPSTATE_ENTRYLIST_H_
