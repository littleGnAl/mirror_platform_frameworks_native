/*
 * Copyright (C) 2008 The Android Open Source Project
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

#define LOG_TAG "IMemory"

#include <android/hidl/allocator/1.1/IAllocator.h>
#include <binder/IMemoryHidl.h>
#include <binder/MemoryBase.h>
#include <binder/MemoryHeapBase.h>
#include <hidl/HidlAshmem.h>
#include <log/log.h>

#define VERBOSE 0

namespace android {

using ::android::hardware::HidlAshmem;
using ::android::hardware::hidl_memory;
using ::android::hidl::allocator::V1_1::IAllocator;
using ::android::hidl::memory::V1_1::memblk;

static const char* kMemName = "ashmem";

static std::mutex mutex;

class MemoryHeapBaseHidl : public MemoryHeapBase {
public:
    static sp<IMemoryHeap> getActive(int64_t heapID) {
        std::unique_lock<std::mutex> lock(mutex);
        if (contains(heapID)) {
            sp<IMemoryHeap> instance = active[heapID].promote();
            if (instance != nullptr) {
                return instance;
            } else {
                active.erase(heapID);
            }
        }
        return nullptr;
    }

    static sp<IMemoryHeap> newInstance(const hidl_memory& mem, int64_t heapID) {
        std::unique_lock<std::mutex> lock(mutex);
        int fd = HidlAshmem::fd(mem);
        if (fd < 0 || heapID < 0) return nullptr;
        sp<IMemoryHeap> instance = new MemoryHeapBaseHidl(fd, mem.size(), heapID);
        return instance;
    }

private:
    static std::map<int64_t, wp<IMemoryHeap> > active;

    static bool contains(int64_t heapID) { return active.count(heapID) > 0; }

    int64_t mHeapID;

    MemoryHeapBaseHidl(int fd, uint64_t size, int64_t heapID)
          : MemoryHeapBase(fd, size), mHeapID(heapID) {
        active[heapID] = this;
    }
    ~MemoryHeapBaseHidl() { active.erase(mHeapID); }
};

std::map<int64_t, wp<IMemoryHeap> > MemoryHeapBaseHidl::active;

sp<HidlAshmem> toHidl(const sp<IMemoryHeap>& heap) {
    int fd = static_cast<int>(heap->getHeapID());
    return HidlAshmem::getInstance(fd, heap->getSize());
}

sp<IMemoryHeap> toBinder(hardware::hidl_memory& mem) {
    int fd = HidlAshmem::fd(mem);
    // not a "ashmem" binderable hidl_memory object
    if (mem.name() != kMemName || fd < 0) {
        ALOGE("toBinder, an unbinderable hidl_memory");
        return nullptr;
    }
    return new MemoryHeapBase(fd, mem.size());
}

sp<IMemory> toBinder(const memblk& memblk) {
    if (memblk.heapID < 0) return nullptr;

    std::unique_lock<std::mutex> lock(mutex);
    sp<IMemoryHeap> heap = MemoryHeapBaseHidl::getActive(memblk.heapID);
    if (heap == nullptr) {
        sp<IAllocator> allocator = IAllocator::getService(kMemName);
        hidl_memory mem;
        allocator->get(memblk.heapID, [&mem](const hidl_memory& _mem) { mem = _mem; });
        if (mem.handle() == nullptr) {
            return nullptr;
        }
        heap = MemoryHeapBaseHidl::newInstance(mem, memblk.heapID);
    }
    return new MemoryBase(heap, memblk.offset, memblk.size);
    ;
}

static std::map<wp<IMemoryHeap>, int64_t> active;

class unregisterHeap : public virtual IBinder::DeathRecipient {
public:
    unregisterHeap(int64_t heapID) : mHeapID(heapID) {}
    virtual void binderDied(const wp<IBinder>&) {
        sp<IAllocator> allocator = IAllocator::getService(kMemName);
        allocator->del(mHeapID);
    }

private:
    int64_t mHeapID;
};

static int64_t registerHeap(sp<IMemory> mem) {
    static std::mutex mutex;
    std::unique_lock<std::mutex> _lock(mutex);
    sp<IMemoryHeap> heap = mem->getMemory();
    wp<IMemoryHeap> key = heap;
    if (active.count(key) > 0) {
        if (key.promote() != nullptr) {
            return active[key];
        } else {
            active.erase(key);
        }
    }
    sp<HidlAshmem> hidl_mem = toHidl(heap);
    sp<IAllocator> allocator = IAllocator::getService(kMemName);
    int64_t heapID = allocator->add(*hidl_mem);

    sp<IBinder> binder = IInterface::asBinder(heap);
    binder->linkToDeath(new unregisterHeap(heapID));
    active[key] = heapID;
    return heapID;
}

memblk toHidl(const sp<IMemory> imemory) {
    memblk memblk;
    memblk.heapID = registerHeap(imemory);
    memblk.offset = imemory->offset();
    memblk.size = imemory->size();
    return memblk;
}

// ---------------------------------------------------------------------------
}; // namespace android
