/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include <android/binder_memory.h>

#include "ibinder_internal.h"

#include <android-base/logging.h>
#include <binder/IMemory.h>
#include <binder/MemoryDealer.h>

using android::IBinder;
using android::IInterface;
using android::IMemory;
using android::MemoryDealer;
using android::sp;

struct AMemory {
    sp<IMemory> memory;  // non-null
};

void AMemory_delete(AMemory* memory) {
    delete memory;
}
void* AMemory_getPointer(const AMemory* memory) {
    if (memory == nullptr) return nullptr;
    return memory->memory->unsecurePointer();
}
size_t AMemory_getSize(const AMemory* memory) {
    if (memory == nullptr) return 0;
    return memory->memory->size();
}
ssize_t AMemory_getOffset(const AMemory* memory) {
    if (memory == nullptr) return 0;
    return memory->memory->offset();
}

__attribute__((warn_unused_result)) AIBinder* AMemory_asBinder(const AMemory* memory) {
    if (memory == nullptr) return nullptr;
    sp<AIBinder> binder = ABpBinder::lookupOrCreateFromBinder(IInterface::asBinder(memory->memory));
    binder->incStrong(nullptr);
    return binder.get();
}
__attribute__((warn_unused_result)) AMemory* AMemory_fromBinder(AIBinder* binder) {
    if (binder == nullptr) return nullptr;
    sp<IMemory> memory = IMemory::asInterface(binder->getBinder());
    CHECK(memory != nullptr);

    return new AMemory{memory};
}

struct AMemoryHeap {
    sp<MemoryDealer> dealer;  // non-null
};

AMemoryHeap* AMemoryHeap_newDealer(size_t size, const char* name, memory_dealer_flags_t flags) {
    sp<MemoryDealer> dealer = new MemoryDealer(size, name, flags);
    return new AMemoryHeap{dealer};
}

void AMemoryHeap_delete(AMemoryHeap* heap) {
    delete heap;
}
AMemory* AMemoryHeap_allocate(AMemoryHeap* heap, size_t size) {
    if (heap == nullptr) return nullptr;
    sp<IMemory> memory = heap->dealer->allocate(size);
    if (memory == nullptr) return nullptr;
    return new AMemory{memory};
}
