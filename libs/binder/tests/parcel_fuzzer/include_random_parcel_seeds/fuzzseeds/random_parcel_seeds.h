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
#include <android-base/hex.h>

#include <binder/Binder.h>
#include <binder/Parcel.h>
#include <binder/RecordedTransaction.h>

#include <private/android_filesystem_config.h>

#include <vector>

using android::Parcel;
using android::base::HexString;
using std::vector;

namespace android {

template <typename T>
status_t writeData(base::borrowed_fd fd, const T* data, size_t byteCount) {
    std::cout <<" byteCount " << byteCount << std::endl;
    const std::byte* dataBytes = reinterpret_cast<const std::byte*>(data);
    std::vector<std::byte> buffer;
    buffer.insert(buffer.end(), dataBytes, dataBytes + byteCount);
    if (!android::base::WriteFully(fd, buffer.data(), buffer.size())) {
        LOG(FATAL) << "Failed to write chunk fd " << fd.get();
        return UNKNOWN_ERROR;
    }

    std::cout <<" Buffer size: "<<  buffer.size() << " Buffer written to fd " << HexString(buffer.data(), buffer.size()) << std::endl;
    return NO_ERROR;
}

template <typename T>
void getReversedBytes(uint8_t* reversedData, size_t& len, T min, T max, T val) {

    std::cout << "val to convert " << val <<  std::endl;

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

    len = index-1;
    std::cout << "Reversed hex " << HexString(reversedData, len) << std::endl;
}

template <typename T>
void writeInBuffer(std::vector<std::byte>& integralBuffer, T min, T max, T val) {
    uint8_t data[10] = {0};
    size_t size = 10;
    getReversedBytes(data, size, min, max, val);

    const std::byte* byteData =  reinterpret_cast<const std::byte*>(&data);
    integralBuffer.insert(integralBuffer.begin(), byteData, byteData + size);
    std::cout << "Buffer "<< HexString(reinterpret_cast<const std::byte*>(integralBuffer.data()), integralBuffer.size()) <<std::endl;
}

template <typename T>
void writeInBuffer(std::vector<std::byte>& integralBuffer, T val) {
    writeInBuffer(integralBuffer, std::numeric_limits<T>::min(), std::numeric_limits<T>::max(), val);
}

void generateSeedsFromRecording(base::unique_fd fd, binder::debug::RecordedTransaction&& transaction) {

    std::cout << "\n\n ############# op 1" << std::endl;
    // Write Reserved bytes for future use
    //uint64_t reservedBytes = 0;
    std::vector<uint8_t> reservedBytes(8, 0);
    writeData(fd, reservedBytes.data(), reservedBytes.size());

    // getReversedBytes give the buffer which can be inserted as is at the end of the data.
    // reversedBytes2->reversedBytes1->reversedBytes0
    std::vector<std::byte> integralBuffer;

    std::cout << "op 2" << std::endl;
    // Write UID array : Array elements are initialized in the order that they are declared
    // UID array index 2 element
    //int64_t aidRoot = 0;
    writeInBuffer(integralBuffer, static_cast<int64_t>(AID_ROOT) << 32, static_cast<int64_t>(AID_USER) << 32, static_cast<int64_t>(AID_ROOT) << 32);

    std::cout << "op 3" << std::endl;
    // UID array index 3 element
   // aidRoot = 0; // TODO: write different UID maybe? This value is never going to be used in seed corpus
    writeInBuffer(integralBuffer, static_cast<int64_t>(AID_ROOT) << 32);

    std::cout << "op 31" << std::endl;
    // always pick AID_ROOT -> index 0

    size_t uidIndex = 0;
    writeInBuffer(integralBuffer, static_cast<size_t>(0), static_cast<size_t>(3), uidIndex);

    std::cout << "op 4" << std::endl;
    // Never set uid in seed corpus
    uint8_t writeUid = 0;
    writeInBuffer(integralBuffer, writeUid);

    std::cout << "op 5" << std::endl;
    // go for reading random code. this will be from recorded transaction
    uint8_t selectCode = 1;
    writeInBuffer(integralBuffer, selectCode);

    std::cout << "op 6" << std::endl;
    uint32_t code = transaction.getCode(); //get from recorded transaction;
    writeInBuffer(integralBuffer, code);

    std::cout << "op 7" << std::endl;
    uint32_t flags = transaction.getFlags(); //get from recorded transaction
    writeInBuffer(integralBuffer, flags);

    std::cout << "op 8" << std::endl; //TODO:DEBUG
    size_t extraBindersIndex = 0; //always produce for main binder - make field in reserved bytes?
    writeInBuffer(integralBuffer, static_cast<size_t>(0), static_cast<size_t>(0), extraBindersIndex);

    std::cout << "op 9" << std::endl;
    const Parcel& dataParcel =  transaction.getDataParcel();

    // subdataSize should be equal to size of this buffer
    std::vector<std::byte> fillParcelBuffer;

    std::cout << "op 10" << std::endl;
    uint8_t rpcBranch = 0; //dont take rpc path
    writeInBuffer(fillParcelBuffer, rpcBranch);

    std::cout << "op 11" << std::endl;
    // implicit branch options->writeHeader(p, provider)
    uint8_t writeHeaderInternal = 1; // always write interface Descriptor
    writeInBuffer(fillParcelBuffer, writeHeaderInternal);

    std::cout << "op 12" << std::endl;
    size_t fillFuncIndex = 0; // write data function
    writeInBuffer(fillParcelBuffer,  static_cast<size_t>(0),  static_cast<size_t>(2), fillFuncIndex); // 3 functions in array

    std::cout << "op 13" << std::endl;
    // Write parcel data size from recorded transaction
    size_t toWrite = transaction.getDataParcel().dataBufferSize();
    writeInBuffer(fillParcelBuffer,  static_cast<size_t>(0), toWrite, toWrite);

    // Write parcel data with size towrite from recorded transaction
    writeData(fd, dataParcel.data(), toWrite);

    std::cout << "op 14" << std::endl;
    //Write Fill Parcel buffer size in integralBuffer so that fuzzService knows size of data
    size_t subDataSize =  toWrite + fillParcelBuffer.size();
    //Write fill parcel buffer
    writeInBuffer(integralBuffer, static_cast<size_t>(0), subDataSize,  subDataSize);

    writeData(fd, fillParcelBuffer.data(), fillParcelBuffer.size());

    std::cout << "op 15" << std::endl;
    // Write the integralBuffer to data
    writeData(fd, integralBuffer.data(), integralBuffer.size());
}
} // namespace android
