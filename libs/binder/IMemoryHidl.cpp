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
#define LOG_TAG "IMemoryHidl"

#include <android/hidl/memory/1.0/IMemory.h>
#include <android/hidl/memory/token/1.0/IMemoryToken.h>
#include <binder/IMemoryHidl.h>
#include <binder/MemoryBase.h>
#include <binder/MemoryHeapBase.h>
#include <hidlmemory/HidlMemoryCache.h>
#include <hidlmemory/HidlMemoryToken.h>
#include <log/log.h>

#define VERBOSE 0

namespace android {

using ::android::hardware::hidl_memory;
using ::android::hardware::hidl_memory_block;
using ::android::hardware::HidlCache;
using ::android::hardware::HidlMemory;
using ::android::hardware::HidlMemoryToken;
using ::android::hardware::IMemoryTokenCompare;
using ::android::hardware::Return;
using ::android::hidl::memory::token::V1_0::IMemoryToken;

static const char* kMemName = "ashmem";

sp<HidlMemory> toHidl(const sp<IMemoryHeap>& heap) {
    int fd = static_cast<int>(heap->getHeapID());
    fd = dup(fd);
    if (fd < 0) {
        ALOGE("toHidl dup fails");
        return nullptr;
    }
    return HidlMemory::getInstance(kMemName, fd, heap->getSize());
}

sp<IMemoryHeap> toBinder(const hidl_memory& mem) {
    // not a "ashmem" binderable hidl_memory object
    int fd = mem.handle()->data[0];
    if (mem.name() != kMemName || fd < 0) {
        ALOGE("toBinder, an unbinderable hidl_memory");
        return nullptr;
    }
    return new MemoryHeapBase(fd, mem.size());
}

class IMemoryHeapCache
      : public virtual HidlCache<sp<IMemoryToken>, IMemoryHeap, IMemoryTokenCompare> {
public:
    static sp<IMemoryHeapCache> getInstance();

protected:
    sp<IMemoryHeap> fill(sp<IMemoryToken> key) override;
    static sp<IMemoryHeapCache> instance;
};

class MemoryHeapBaseCacheable : public MemoryHeapBase {
public:
    MemoryHeapBaseCacheable(int fd, uint64_t size, sp<IMemoryToken> key)
          : MemoryHeapBase(fd, size), mKey(key) {}
    virtual ~MemoryHeapBaseCacheable() { IMemoryHeapCache::getInstance()->flush(mKey); }

protected:
    sp<IMemoryToken> mKey;
};

sp<IMemoryHeapCache> IMemoryHeapCache::instance = nullptr;

sp<IMemoryHeapCache> IMemoryHeapCache::getInstance() {
    if (instance == nullptr) {
        instance = new IMemoryHeapCache();
    }
    return instance;
}

sp<IMemoryHeap> IMemoryHeapCache::fill(sp<IMemoryToken> key) {
    sp<IMemoryHeap> heap = nullptr;
    Return<void> ret = key->get([&](const hidl_memory& mem) {
        heap = new MemoryHeapBaseCacheable(mem.handle()->data[0], mem.size(), key);
    });
    if (!ret.isOk()) {
        ALOGE("Cannot get.");
        return nullptr;
    }
    mCached[key] = heap;
    return heap;
}

sp<IMemory> toBinder(const hidl_memory_block& memblk) {
    Return<sp<IMemoryToken>> ret = IMemoryToken::castFrom(memblk.token());
    if (!ret.isOk()) {
        ALOGE("Cannot map.");
        return nullptr;
    }
    sp<IMemoryToken> token = ret;
    sp<IMemoryHeap> heap = IMemoryHeapCache::getInstance()->fetch(token);
    return new MemoryBase(heap, memblk.size(), memblk.offset());
}

struct IMemoryHeapCompare {
    bool operator()(const sp<IMemoryHeap>& lhs, const sp<IMemoryHeap>& rhs) const {
        sp<IBinder> lb = IMemoryHeap::asBinder(lhs);
        sp<IBinder> rb = IMemoryHeap::asBinder(rhs);
        return lb < rb;
    }
};

class IMemoryTokenCache
      : public virtual HidlCache<sp<IMemoryHeap>, IMemoryToken, IMemoryHeapCompare> {
public:
    static sp<IMemoryTokenCache> getInstance();

protected:
    sp<IMemoryToken> fill(sp<IMemoryHeap> key) override;
    static sp<IMemoryTokenCache> instance;
};

sp<IMemoryTokenCache> IMemoryTokenCache::instance = nullptr;

sp<IMemoryTokenCache> IMemoryTokenCache::getInstance() {
    if (instance == nullptr) {
        instance = new IMemoryTokenCache();
    }
    return instance;
}

class HidlMemoryTokenCacheable : public virtual HidlMemoryToken {
public:
    HidlMemoryTokenCacheable(sp<HidlMemory> memory, sp<IMemoryHeap> key) : HidlMemoryToken(memory) {
        mKey = key;
    }
    virtual ~HidlMemoryTokenCacheable() { IMemoryTokenCache::getInstance()->flush(mKey); }

protected:
    sp<IMemoryHeap> mKey;
};

sp<IMemoryToken> IMemoryTokenCache::fill(sp<IMemoryHeap> key) {
    int fd = key->getHeapID();
    sp<HidlMemory> hmem = HidlMemory::getInstance(kMemName, fd, key->getSize());
    sp<IMemoryToken> token = new HidlMemoryTokenCacheable(hmem, key);
    mCached[key] = token;
    return token;
}

hidl_memory_block toHidl(const sp<IMemory>& memory) {
    sp<IMemoryHeap> heap = memory->getMemory();
    sp<IMemoryToken> token = IMemoryTokenCache::getInstance()->fetch(heap);
    return hidl_memory_block(token, memory->size(), memory->offset());
}
// ---------------------------------------------------------------------------
}; // namespace android
