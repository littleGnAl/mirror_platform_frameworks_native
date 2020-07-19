/*
 * Copyright 2020 The Android Open Source Project
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

#include <binder/MemoryDealer.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <string>
#include <unordered_set>

namespace android {

static constexpr size_t kMaxBufferSize = 10000;
static constexpr size_t kMaxDealerSize = 1024 * 512;
static constexpr size_t kMaxAllocSize = 1024;

// This is used to track offsets that have been freed already to avoid an expected fatal log.
static std::unordered_set<size_t> kFreeList;

/* This is a vector of lambda functions the fuzzer will pull from.
 *  This is done so new functions can be added to the fuzzer easily
 *  without requiring modifications to the main fuzzer file. This also
 *  allows multiple fuzzers to include this file, if functionality is needed.
 */
static const std::vector<std::function<void(FuzzedDataProvider*, const sp<MemoryDealer>&)>>
        gMemoryDealerOperations =
                {[](FuzzedDataProvider*, const sp<MemoryDealer>& dealer) -> void {
                     dealer->getAllocationAlignment();
                 },
                 [](FuzzedDataProvider*, const sp<MemoryDealer>& dealer) -> void {
                     dealer->getMemoryHeap();
                 },
                 [](FuzzedDataProvider* fdp, const sp<MemoryDealer>& dealer) -> void {
                     size_t offset = fdp->ConsumeIntegral<size_t>();

                     // Offset has already been freed, so return instead.
                     if (kFreeList.find(offset) != kFreeList.end()) return;

                     dealer->deallocate(offset);
                     kFreeList.insert(offset);
                 },
                 [](FuzzedDataProvider* fdp, const sp<MemoryDealer>& dealer) -> void {
                     std::string randString =
                             fdp->ConsumeRandomLengthString(fdp->remaining_bytes());
                     dealer->dump(randString.c_str());
                 },
                 [](FuzzedDataProvider* fdp, const sp<MemoryDealer>& dealer) -> void {
                     size_t allocSize = fdp->ConsumeIntegralInRange<size_t>(0, kMaxAllocSize);
                     sp<IMemory> allocated = dealer->allocate(allocSize);
                     // If the allocation was successful, try to write to it
                     if (allocated != nullptr && allocated->unsecurePointer() != nullptr) {
                         memset(allocated->unsecurePointer(), 1, allocated->size());

                         // Clear the address from freelist since it has been allocated over again.
                         kFreeList.erase(allocated->offset());
                     }
                 }};

} // namespace android
