/*
 * Copyright (C) 2023 The Android Open Source Project
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

#include <android-base/file.h>
#include <android-base/logging.h>

#include <binder/RecordedTransaction.h>

#include <fuzzseeds/random_parcel_seeds.h>

namespace android {
template <typename T>
status_t writeData(base::borrowed_fd fd, const T* data, size_t byteCount) {
    const std::byte* dataBytes = reinterpret_cast<const std::byte*>(data);
    std::vector<std::byte> buffer;
    buffer.insert(buffer.end(), dataBytes, dataBytes + byteCount);
    if (!android::base::WriteFully(fd, buffer.data(), buffer.size())) {
        LOG(FATAL) << "Failed to write chunk fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    return NO_ERROR;
}

template <typename T>
void getReversedBytes(uint8_t* reversedData, size_t& len, T min, T max, T val) {
    uint64_t range = static_cast<uint64_t>(max) - min;
    uint64_t result = val - min;
    size_t offset = 0;
    size_t index = 0;

    reversedData[index] = reversedData[index] | result;
    index++;
    while (offset < sizeof(T) * CHAR_BIT && (range >> offset) > 0 && index < len) {
        reversedData[index] = reversedData[index] | (result >> CHAR_BIT);
        result = result >> CHAR_BIT;
        offset += CHAR_BIT;
        index++;
    }

    // Update the provided length to actual bytes which have been written to provided buffer
    // TODO: Find a better way to do this
    len = index - 1;
}

template <typename T>
void writeInBuffer(std::vector<std::byte>& integralBuffer, T min, T max, T val) {
    // TODO: use vector here
    size_t dataSize = 10;
    uint8_t data[10] = {0};

    getReversedBytes(data, dataSize, min, max, val);

    const std::byte* byteData = reinterpret_cast<const std::byte*>(&data);

    // ConsumeIntegral Calls read buffer from the end. Keep inserting at the front of the buffer
    // so that we can align fuzzService operations with seed generation for readability.
    integralBuffer.insert(integralBuffer.begin(), byteData, byteData + dataSize);
}

template <typename T>
void writeInBuffer(std::vector<std::byte>& integralBuffer, T val) {
    // For ConsumeIntegral<T>() calls, FuzzedDataProvider uses numeric limits min and max
    // as range
    writeInBuffer(integralBuffer, std::numeric_limits<T>::min(), std::numeric_limits<T>::max(),
                  val);
}

void generateSeedsFromRecording(base::borrowed_fd fd,
                                binder::debug::RecordedTransaction&& transaction) {
    // Write Reserved bytes for future use
    std::vector<uint8_t> reservedBytes(8);
    writeData(fd, reservedBytes.data(), reservedBytes.size());

    std::vector<std::byte> integralBuffer;

    // Write UID array : Array elements are initialized in the order that they are declared
    // UID array index 2 element
    // int64_t aidRoot = 0;
    writeInBuffer(integralBuffer, static_cast<int64_t>(AID_ROOT) << 32,
                  static_cast<int64_t>(AID_USER) << 32, static_cast<int64_t>(AID_ROOT) << 32);

    // UID array index 3 element
    writeInBuffer(integralBuffer, static_cast<int64_t>(AID_ROOT) << 32);

    // always pick AID_ROOT -> index 0
    size_t uidIndex = 0;
    writeInBuffer(integralBuffer, static_cast<size_t>(0), static_cast<size_t>(3), uidIndex);

    // Never set uid in seed corpus
    uint8_t writeUid = 0;
    writeInBuffer(integralBuffer, writeUid);

    // Read random code. this will be from recorded transaction
    uint8_t selectCode = 1;
    writeInBuffer(integralBuffer, selectCode);

    // Get from recorded transaction
    uint32_t code = transaction.getCode();
    writeInBuffer(integralBuffer, code);

    // Get from recorded transaction
    uint32_t flags = transaction.getFlags();
    writeInBuffer(integralBuffer, flags);

    // always fuzz primary binder
    size_t extraBindersIndex = 0;
    writeInBuffer(integralBuffer, static_cast<size_t>(0), static_cast<size_t>(0),
                  extraBindersIndex);

    const Parcel& dataParcel = transaction.getDataParcel();

    // subdataSize should be equal to size of this buffer plus actual parcel size
    std::vector<std::byte> fillParcelBuffer;

    // Don't take rpc path
    uint8_t rpcBranch = 0;
    writeInBuffer(fillParcelBuffer, rpcBranch);

    // Implicit branch on this path -> options->writeHeader(p, provider)
    uint8_t writeHeaderInternal = 1; // always write interface Descriptor
    writeInBuffer(fillParcelBuffer, writeHeaderInternal);

    // Choose to write data in parcel
    size_t fillFuncIndex = 3;
    writeInBuffer(fillParcelBuffer, static_cast<size_t>(0), static_cast<size_t>(3), fillFuncIndex);

    // Write parcel data size from recorded transaction
    size_t toWrite = transaction.getDataParcel().dataBufferSize();
    writeInBuffer(fillParcelBuffer, static_cast<size_t>(0), toWrite, toWrite);

    // Write parcel data with size towrite from recorded transaction
    writeData(fd, dataParcel.data(), toWrite);

    // Write Fill Parcel buffer size in integralBuffer so that fuzzService knows size of data
    size_t subDataSize = toWrite + fillParcelBuffer.size();
    // Write fill parcel buffer
    writeInBuffer(integralBuffer, static_cast<size_t>(0), subDataSize, subDataSize);

    writeData(fd, fillParcelBuffer.data(), fillParcelBuffer.size());

    // Write the integralBuffer to data
    writeData(fd, integralBuffer.data(), integralBuffer.size());
}
} // namespace android
