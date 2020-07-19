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

#ifndef PARCEL_FUZZER_FUNCTIONS_H_
#define PARCEL_FUZZER_FUNCTIONS_H_

#include <binder/IPCThreadState.h>
#include <binder/Parcel.h>
#include <binder/TextOutput.h>
#include <fuzzer/FuzzedDataProvider.h>
#include <string.h>
#include "FlattenableClasses.h"
#include "commonFuzzHelpers.h"

#define MAX_NUM_PARCELS 128
#define PARCEL_DATA_MAXSIZE 65536
#define PARCEL_MAX_IFACE_NAME_LEN 2048
#define MAX_ALLOC_SIZE 65536

std::vector<std::shared_ptr<android::Parcel>> parcelVector;

void parcelFuzzCleanup() {
    parcelVector.clear();
}

android::Parcel* getArbitraryParcel(FuzzedDataProvider* fdp) {
    if (parcelVector.empty()) {
        return nullptr;
    } else {
        return getArbitraryVectorElement(fdp, parcelVector, false).get();
    }
}

// "peeks" a parcel int32 value without advancing pointer,
// for checking vector size
int32_t peekParcelVectorSize(android::Parcel* parcel) {
    if (parcel == nullptr) {
        return -1;
    }
    int32_t current_pos = parcel->dataPosition();
    int32_t retVal;
    parcel->readInt32(&retVal);
    parcel->setDataPosition(current_pos);
    return retVal;
}

// Force the size of a vector for a read operation to be a "sane" value, to
// prevent memory allocation issues from trying to allocate a vector of
// max_size_t elements
void parcelReadForceValidSize(FuzzedDataProvider* fdp, android::Parcel* parcel,
                              size_t element_size) {
    // Peek the existing size
    int32_t size = peekParcelVectorSize(parcel);

    // If size is invalid, write our own
    int32_t max_elements = MAX_ALLOC_SIZE / static_cast<int32_t>(element_size);

    if (size < 0 || size > max_elements) {
        size_t current_pos = parcel->dataPosition();
        size = fdp->ConsumeIntegralInRange<int32_t>(0, max_elements);
        parcel->writeInt32(size);
        parcel->setDataPosition(current_pos);
    }
}

/* This is a vector of lambda functions the fuzzer will pull from.
 *  This is done so new functions can be added to the fuzzer easily
 *  without requiring modifications to the main fuzzer file. This also
 *  allows multiple fuzzers to include this file, if functionality is needed.
 */
static const std::vector<std::function<void(FuzzedDataProvider*)>> parcel_operations = {
        // Parcel()
        [](FuzzedDataProvider*) -> void {
            if (parcelVector.size() < MAX_NUM_PARCELS) {
                std::shared_ptr<android::Parcel> parcel(new android::Parcel());
                if (parcel) {
                    parcelVector.push_back(parcel);
                }
            }
        },

        // ~Parcel()
        [](FuzzedDataProvider* fdp) -> void {
            if (parcelVector.empty()) {
                return;
            }
            size_t index = fdp->ConsumeIntegralInRange<size_t>(0, parcelVector.size() - 1);
            parcelVector.erase(parcelVector.begin() + index);
        },

        // data()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->data();
            }
        },

        // dataSize()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->dataSize();
            }
        },

        // dataAvail()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->dataAvail();
            }
        },

        // dataPosition()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->dataPosition();
            }
        },

        // dataCapacity()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->dataCapacity();
            }
        },

        // setDataSize(size_t size)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                size_t prev_size = parcel->dataSize();
                parcel->setDataSize(fdp->ConsumeIntegralInRange(0, PARCEL_DATA_MAXSIZE));
                // If buffer size increased, zero out the extra space
                size_t new_size = parcel->dataSize();
                if (new_size > prev_size) {
                    uint8_t* end_data_ptr =
                            const_cast<uint8_t*>(parcel->data()) + parcel->dataPosition();
                    std::memset(end_data_ptr, 0, new_size - prev_size);
                }
            }
        },

        // setDataPosition(size_t pos)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                // Call will assert if we set position too far
                parcel->setDataPosition(fdp->ConsumeIntegralInRange<size_t>(0, INT32_MAX));
            }
        },

        // setDataCapacity(size_t size)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                size_t prev_size = parcel->dataSize();
                parcel->setDataCapacity(fdp->ConsumeIntegralInRange(0, PARCEL_DATA_MAXSIZE));
                // If buffer size increased, zero out the extra space
                size_t new_size = parcel->dataSize();
                if (new_size > prev_size) {
                    uint8_t* end_data_ptr =
                            const_cast<uint8_t*>(parcel->data()) + parcel->dataPosition();
                    std::memset(end_data_ptr, 0, new_size - prev_size);
                }
            }
        },

        // setData(const uint8_t* buffer, size_t len)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                size_t buf_size = fdp->ConsumeIntegralInRange(0, PARCEL_DATA_MAXSIZE);
                std::vector<uint8_t> data = fdp->ConsumeBytes<uint8_t>(buf_size);
                if (data.empty()) {
                    return;
                }

                parcel->setData(data.data(), data.size());
            }
        },

        // appendFrom(const Parcel *parcel, size_t start, size_t len)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->appendFrom(getArbitraryParcel(fdp), fdp->ConsumeIntegral<size_t>(),
                                   fdp->ConsumeIntegralInRange<size_t>(0, PARCEL_DATA_MAXSIZE));
            }
        },

        // compareData(const Parcel& other)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                if (android::Parcel* otherParcel = getArbitraryParcel(fdp)) {
                    parcel->compareData(*otherParcel);
                }
            }
        },

        // allowFds()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->allowFds();
            }
        },

        // pushAllowFds(bool allowFds)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->pushAllowFds(fdp->ConsumeBool());
            }
        },

        // restoreAllowFds(bool lastValue)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->restoreAllowFds(fdp->ConsumeBool());
            }
        },

        // pushAllowFds(bool allowFds)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->pushAllowFds(fdp->ConsumeBool());
            }
        },

        // hasFileDescriptors()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->hasFileDescriptors();
            }
        },

        // writeInterfaceToken(const String16& interface)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                std::string ifaceName = fdp->ConsumeRandomLengthString(PARCEL_MAX_IFACE_NAME_LEN);
                android::String16 interface(ifaceName.c_str());
                parcel->writeInterfaceToken(interface);
            }
        },

        // enforceInterface(const String16& interface, IPCThreadState* threadState = nullptr)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                std::string ifaceName = fdp->ConsumeRandomLengthString(PARCEL_MAX_IFACE_NAME_LEN);
                android::String16 interface(ifaceName.c_str());
                android::IPCThreadState* threadState = android::IPCThreadState::self();
                if (threadState) {
                    threadState->setLastTransactionBinderFlags(fdp->ConsumeIntegral<int32_t>());
                    parcel->enforceInterface(interface, threadState);
                }
            }
        },

        // enforceInterface(const char16_t* interface, size_t len, IPCThreadState* threadState =
        // nullptr)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                std::string ifaceName = fdp->ConsumeRandomLengthString(PARCEL_MAX_IFACE_NAME_LEN);
                android::String16 interface(ifaceName.c_str());
                android::IPCThreadState* threadState = android::IPCThreadState::self();
                if (threadState) {
                    threadState->setLastTransactionBinderFlags(fdp->ConsumeIntegral<int32_t>());
                    parcel->enforceInterface(interface, interface.size(), threadState);
                }
            }
        },

        // checkInterface(IBinder*)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                // TODO: Ideally we'd get these BBinder objects to varying states so
                //       getInterfaceDescriptor() returns different values.
                android::sp<android::IBinder> bbinder = new android::BBinder();
                parcel->checkInterface(bbinder.get());
            }
        },

        // freeData()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->freeData();
            }
        },

        // objectsCount()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->objectsCount();
            }
        },

        // errorCheck()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->errorCheck();
            }
        },

        // setError(status_t err)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->setError(fdp->ConsumeIntegral<android::status_t>());
            }
        },

        // write(const void* data, size_t len)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                std::vector<uint8_t> data = fdp->ConsumeBytes<uint8_t>(
                        fdp->ConsumeIntegralInRange(0, PARCEL_DATA_MAXSIZE));
                parcel->write(data.data(), data.size());
            }
        },

        // writeInplace(size_t len)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->writeInplace(fdp->ConsumeIntegralInRange(0, PARCEL_DATA_MAXSIZE));
            }
        },

        // writeUnpadded(const void* data, size_t len)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                std::vector<uint8_t> data = fdp->ConsumeBytes<uint8_t>(
                        fdp->ConsumeIntegralInRange(0, PARCEL_DATA_MAXSIZE));
                parcel->write(data.data(), data.size());
            }
        },

        // writeInt32(int32_t val)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->writeInt32(fdp->ConsumeIntegral<int32_t>());
            }
        },

        // writeByteVector(const std::optional<std::vector<int8_t>>& val)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                size_t len = fdp->ConsumeIntegralInRange<size_t>(0, PARCEL_DATA_MAXSIZE);
                std::optional<std::vector<int8_t>> val;
                std::vector<int8_t> bytes = fdp->ConsumeBytes<int8_t>(len);
                val.emplace(bytes);
                parcel->writeByteVector(val);
            }
        },

        // writeInt32Vector(const std::optional<std::vector<int32_t>>& val)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                size_t len = fdp->ConsumeIntegralInRange<size_t>(0, PARCEL_DATA_MAXSIZE / 4);
                std::optional<std::vector<int32_t>> val;
                std::vector<int8_t> bytes = fdp->ConsumeBytes<int8_t>(len * 4);
                std::vector<int32_t> bytes32(bytes.data(), bytes.data() + (bytes.size() / 4));
                val.emplace(bytes32);

                parcel->writeInt32Vector(val);
            }
        },

        // writeInt32Vector(const std::vector<int32_t>& val)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                size_t len = fdp->ConsumeIntegralInRange<size_t>(0, PARCEL_DATA_MAXSIZE / 4);
                std::vector<int8_t> bytes = fdp->ConsumeBytes<int8_t>(len * 4);
                std::vector<int32_t> bytes32(bytes.data(), bytes.data() + (bytes.size() / 4));
                parcel->writeInt32Vector(bytes32);
            }
        },

        // writeNoException()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->writeNoException();
            }
        },

        // read(void* outData, size_t len)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                size_t len = fdp->ConsumeIntegralInRange(0, PARCEL_DATA_MAXSIZE);
                if (void* buf = malloc(len)) {
                    parcel->read(buf, len);
                    free(buf);
                }
            }
        },

        // readInplace(size_t len)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->readInplace(fdp->ConsumeIntegral<size_t>());
            }
        },

        // readInt32()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->readInt32();
            }
        },

        // readCString()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->readCString();
            }
        },

        // readString8()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->readString8();
            }
        },

        // readString8(String8* pArg)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                android::String8 retString;
                parcel->readString8(&retString);
            }
        },

        // readString16()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->readString16();
            }
        },

        // readStrongBinder()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->readStrongBinder();
            }
        },

        // readStrongBinder(sp<IBinder>* val)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                android::sp<android::IBinder> val;
                parcel->readStrongBinder(&val);
            }
        },

        // readNullableStrongBinder(sp<IBinder>* val)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                android::sp<android::IBinder> val;
                parcel->readNullableStrongBinder(&val);
            }
        },

        // readByteVector(std::optional<std::vector<int8_t>>* val)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcelReadForceValidSize(fdp, parcel, sizeof(int8_t));
                std::optional<std::vector<int8_t>> val;
                parcel->readByteVector(&val);
            }
        },

        // readInt32Vector(std::optional<std::vector<int32_t>>* val)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcelReadForceValidSize(fdp, parcel, sizeof(int32_t));
                std::optional<std::vector<int32_t>> val;
                parcel->readInt32Vector(&val);
            }
        },

        // readInt32Vector(std::unique_ptr<std::vector<int32_t>>* val)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcelReadForceValidSize(fdp, parcel, sizeof(int32_t));
                std::unique_ptr<std::vector<int32_t>> val;
                parcel->readInt32Vector(&val);
            }
        },

        // readInt32Vector(std::vector<int32_t>* val)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcelReadForceValidSize(fdp, parcel, sizeof(int32_t));
                std::vector<int32_t> val;
                parcel->readInt32Vector(&val);
            }
        },

        // read(Flattenable<T>& val)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                android::Flattenable<android::FuzzFlattenable> retVal;
                parcel->read(retVal);
            }
        },

        // read(LightFlattenable<T>& val)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                android::LightFlattenable<android::FuzzLightFlattenable> retVal;
                parcel->read(retVal);
            }
        },

        // resizeOutVector(std::vector<T>* val)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcelReadForceValidSize(fdp, parcel, sizeof(uint8_t));
                std::vector<uint8_t> retVal;
                parcel->resizeOutVector(&retVal);
            }
        },

        // resizeOutVector(std::optional<std::vector<T>>* val)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcelReadForceValidSize(fdp, parcel, sizeof(uint8_t));
                std::optional<std::vector<uint8_t>> retVal;
                parcel->resizeOutVector(&retVal);
            }
        },

        // resizeOutVector(std::unique_ptr<std::vector<T>>* val)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcelReadForceValidSize(fdp, parcel, sizeof(uint8_t));
                std::unique_ptr<std::vector<uint8_t>> retVal;
                parcel->resizeOutVector(&retVal);
            }
        },

        // reserveOutVector(std::vector<T>* val, size_t* size)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcelReadForceValidSize(fdp, parcel, sizeof(uint8_t));
                std::vector<uint8_t> retVal;
                size_t retSize;
                parcel->reserveOutVector(&retVal, &retSize);
            }
        },

        // reserveOutVector(std::optional<std::vector<T>>* val, size_t* size)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcelReadForceValidSize(fdp, parcel, sizeof(uint8_t));
                std::optional<std::vector<uint8_t>> retVal;
                size_t retSize;
                parcel->reserveOutVector(&retVal, &retSize);
            }
        },

        // reserveOutVector(std::unique_ptr<std::vector<T>>* val, size_t* size)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcelReadForceValidSize(fdp, parcel, sizeof(uint8_t));
                std::unique_ptr<std::vector<uint8_t>> retVal;
                size_t retSize;
                parcel->reserveOutVector(&retVal, &retSize);
            }
        },

        // readExceptionCode()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->readExceptionCode();
            }
        },

        // readNativeHandle()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->readNativeHandle();
            }
        },

        // readFileDescriptor()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->readFileDescriptor();
            }
        },

        // readParcelFileDescriptor()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->readParcelFileDescriptor();
            }
        },

        // readUniqueFileDescriptor(base::unique_fd* val)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                android::base::unique_fd fd;
                parcel->readUniqueFileDescriptor(&fd);
            }
        },

        // readUniqueParcelFileDescriptor(base::unique_fd* val)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                android::base::unique_fd fd;
                parcel->readUniqueParcelFileDescriptor(&fd);
            }
        },

        // readUniqueFileDescriptorVector(std::optional<std::vector<base::unique_fd>>* val)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcelReadForceValidSize(fdp, parcel, sizeof(android::base::unique_fd));
                std::optional<std::vector<android::base::unique_fd>> val;
                parcel->readUniqueFileDescriptorVector(&val);
            }
        },

        // readUniqueFileDescriptorVector(std::unique_ptr<std::vector<base::unique_fd>>* val)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcelReadForceValidSize(fdp, parcel, sizeof(android::base::unique_fd));
                std::unique_ptr<std::vector<android::base::unique_fd>> val;
                parcel->readUniqueFileDescriptorVector(&val);
            }
        },

        // readUniqueFileDescriptorVector(std::vector<base::unique_fd>* val)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcelReadForceValidSize(fdp, parcel, sizeof(android::base::unique_fd));
                std::vector<android::base::unique_fd> val;
                parcel->readUniqueFileDescriptorVector(&val);
            }
        },

        // readBlob(size_t len, ReadableBlob* outBlob)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                android::Parcel::ReadableBlob outBlob;
                parcel->readBlob(fdp->ConsumeIntegral<size_t>(), &outBlob);
            }
        },

        // readObject(bool nullMetaData)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->readObject(fdp->ConsumeBool());
            }
        },

        // closeFileDescriptors()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->closeFileDescriptors();
            }
        },

        // getGlobalAllocSize()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->getGlobalAllocSize();
            }
        },

        // getGlobalAllocCount()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->getGlobalAllocCount();
            }
        },

        // replaceCallingWorkSourceUid(uid_t uid)
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->replaceCallingWorkSourceUid(fdp->ConsumeIntegral<uid_t>());
            }
        },

        // readCallingWorkSourceUid()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->readCallingWorkSourceUid();
            }
        },

        // NOTE: This function works, but is omitted due to the large size of
        //       Parcel objects, and the slowdown from repeated calls leading
        //       to slow-unit cases as well as cluttered fuzzer output.
        // // print(TextOutput& to, uint32_t flags = 0)
        // [](FuzzedDataProvider* fdp) -> void {
        //     if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
        //         android::TextOutput* to = nullptr;
        //         switch (fdp->ConsumeIntegralInRange<size_t>(0, 2)) {
        //             case 0:
        //                 to = &android::aout;
        //                 break;
        //             case 1:
        //                 to = &android::alog;
        //                 break;
        //             case 2:
        //                 to = &android::aerr;
        //                 break;
        //         }
        //         parcel->print(*to, fdp->ConsumeIntegral<uint32_t>());
        //     }
        // },

        // getBlobAshmemSize()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->getBlobAshmemSize();
            }
        },

        // getOpenAshmemSize()
        [](FuzzedDataProvider* fdp) -> void {
            if (android::Parcel* parcel = getArbitraryParcel(fdp)) {
                parcel->getOpenAshmemSize();
            }
        },
};

#endif // PARCEL_FUZZER_FUNCTIONS_H_
