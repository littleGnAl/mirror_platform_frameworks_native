/*
 * Copyright (C) 2020 The Android Open Source Project
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
#include "binder/ShmemCompat.h"

#include "binder/MemoryBase.h"
#include "binder/MemoryHeapBase.h"
#include "binder/ShmemUtil.h"

namespace android {

using os::SharedMemory;

bool convertSharedMemoryToIMemory(const os::SharedMemory& shmem,
                                  sp<IMemory>* result) {
    if (!validateSharedMemory(shmem)) {
        return false;
    }

    if (shmem.fd.get() < 0) {
        *result = nullptr;
        return true;
    }

    // Heap offset and size must be page aligned.
    size_t pageSize = getpagesize();
    size_t pageMask = ~(pageSize - 1);

    size_t endOffset = shmem.offset + shmem.size;

    // Round down to page boundary.
    size_t heapStartOffset = shmem.offset & pageMask;
    // Round up to page boundary.
    size_t heapEndOffset = (endOffset + pageSize - 1) & pageMask;
    size_t heapSize = heapEndOffset - heapStartOffset;

    sp<MemoryHeapBase> heap =
            new MemoryHeapBase(shmem.fd.get(), heapSize, 0, heapStartOffset);
    *result = sp<MemoryBase>::make(heap,
                                   shmem.offset - heapStartOffset,
                                   shmem.size);
    return true;
}

bool convertIMemoryToSharedMemory(const sp<IMemory>& mem,
                                  os::SharedMemory* result) {
    if (mem == nullptr) {
        *result = os::SharedMemory();
    }

    ssize_t offset;
    size_t size;

    sp<IMemoryHeap> heap = mem->getMemory(&offset, &size);
    if (heap != nullptr) {
        // Make sure the offset and size do not overflow from int32 boundaries.
        if (size > std::numeric_limits<int32_t>::max() ||
                offset > std::numeric_limits<int32_t>::max() ||
                heap->getOffset() > std::numeric_limits<int32_t>::max() ||
                heap->getOffset() + offset
                        > std::numeric_limits<int32_t>::max()) {
            return false;
        }

        result->fd.reset(base::unique_fd(fcntl(heap->getHeapID(),
                                               F_DUPFD_CLOEXEC,
                                               0)));
        result->size = size;
        result->offset = heap->getOffset() + offset;
    }

    return true;
}

}  // namespace android
