#include "binder/ShmemCompat.h"

#include "binder/MemoryBase.h"
#include "binder/MemoryHeapBase.h"

namespace android {

using os::SharedMemory;

sp<IMemory> convertSharedMemoryToIMemory(const SharedMemory& shmem) {
    if (!shmem.fd.ok()) {
        return nullptr;
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
    return new MemoryBase(heap, shmem.offset - heapStartOffset, shmem.size);
}

SharedMemory convertIMemoryToSharedMemory(const sp<IMemory>& mem) {
    SharedMemory result;

    if (mem == nullptr) {
        return result;
    }

    ssize_t offset;
    size_t size;
    sp<IMemoryHeap> heap = mem->getMemory(&offset, &size);
    if (heap != nullptr) {
        result.fd =
                base::unique_fd(fcntl(heap->getHeapID(), F_DUPFD_CLOEXEC, 0));
        result.size = size;
        result.offset = heap->getOffset() + offset;
    }

    return result;
}

}  // namespace android
