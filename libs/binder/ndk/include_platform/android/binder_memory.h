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

#pragma once

#include <android/binder_ibinder.h>

__BEGIN_DECLS

#if __ANDROID_API__ >= __ANDROID_API_R__

/**
 * Represents an allocation of shared memory within a larger region.
 */
struct AMemory;
typedef struct AMemory AMemory;

/**
 * Delete AMemory object.
 *
 * \param memory object to delete
 */
void AMemory_delete(AMemory* memory);

/**
 * Get pointer to memory region represented by this memory object. If the
 * underlying shared memory is not already mapped, it will be mapped. This
 * already takes into account the offset described below. If X is returned, then
 * this object represents the memory from X to X + AMemory_getSize.
 *
 * WARNING
 * WARNING This is shared memory. It may change from under you.
 * WARNING
 *
 * \param memory region pointer should be retrieved from
 * \return pointer to memory region of size AMemory_getSize or nullptr on error
 */
void* AMemory_getPointer(const AMemory* memory);

/**
 * Get size of the memory region being mapped. This memory object represents an
 * allocation of this size.
 *
 * \param memory allocation whose size is being requested
 * \return size in bytes
 */
size_t AMemory_getSize(const AMemory* memory);

/**
 * Get offset of the memory region in the larger allocation. This is already
 * accounted for by AMemory_getPointer.
 *
 * \param memory allocation whose offset is being requested
 * \return offset from base of underlying heap
 */
ssize_t AMemory_getOffset(const AMemory* memory);

/**
 * Get a binder object representing a memory region. If it is sent to another
 * process, that process can also use this memory.
 *
 * \param memory allocation to be converted to a binder
 * \return binder object with one refcount
 */
__attribute__((warn_unused_result)) AIBinder* AMemory_asBinder(const AMemory* memory);

/**
 * Get an AMemory object from a binder that was originally allocated with this
 * API. Result must be deleted with AMemory_delete.
 *
 * \param binder representation of an IMemory object
 * \return AMemory representation or nullptr
 */
__attribute__((warn_unused_result)) AMemory* AMemory_fromBinder(AIBinder* binder);

/**
 * Represents a single shared memory object from which multiple allocation (see
 * AMemory above) can be made. The motivation of this object is that the
 * underlying buffer from the heap can easily be sent to another process and
 * mapped, and multiple IMemory objects can be sent and retrieved without having
 * to do another expensive mapping operation.
 */
struct AMemoryHeap;
typedef struct AMemoryHeap AMemoryHeap;

typedef uint32_t memory_dealer_flags_t;
enum {
    NONE = 0x0,

    /**
     * Request that the memory is read only by other processes.
     */
    READ_ONLY = 0x1,
    /**
     * Request the memory to only be mapped in remote processes. This means that
     * AMemory_getPointer won't be available locally.
     */
    DONT_MAP_LOCALLY = 0x100,
    /**
     * Writes to memory will be done w/ O_SYNC.
     */
    NO_CACHING = 0x200,
};

/**
 * Create a region of shared memory which can have allocations within it.
 *
 * \param size total size of shared memory region
 * \param name may be nullptr, for debugging
 * \param flags see memory_dealer_flags_t
 * \return heap, must be deleted with AMemoryHeap_delete
 */
__attribute__((warn_unused_result)) AMemoryHeap* AMemoryHeap_newDealer(size_t size,
                                                                       const char* name,
                                                                       memory_dealer_flags_t flags);

/**
 * Delete a heap.
 *
 * FIXME: figure out and document what happens to underlying memory.
 *
 * \param heap heap to delete
 */
void AMemoryHeap_delete(AMemoryHeap* heap);

/**
 * Allocate within a memory heap.
 *
 * \param heap heap where allocation comes from
 * \param size size of allocation to be made
 * \return allocation, must be deleted with AMemory_delete
 */
__attribute__((warn_unused_result)) AMemory* AMemoryHeap_allocate(AMemoryHeap* heap, size_t size);

#endif  // > R

__END_DECLS
