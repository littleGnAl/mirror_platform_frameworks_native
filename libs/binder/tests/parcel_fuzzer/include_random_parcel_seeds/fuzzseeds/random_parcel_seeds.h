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

#include <vector>

using android::base::HexString;
using std::vector;

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

void generateSeedsFromRecording(base::unique_fd fd, binder::debug::RecordedTransaction&& transaction) {
    //TODO: Write 8 reservedBytes

    //TODO: This won't work because ConsumeIntegralInRange performs series of operations
    // and takes the bytes from the end of the fuzzed data. We need to reverse the operation listed
    // here in order to read back correct byte. Another option is to generate all sequences of bytes
    // and see if that reaches target value for the same API and write those bytes.
    // https://cs.android.com/android/platform/superproject/main/+/main:prebuilts/clang-tools/linux-x86/lib64/clang/17/include/fuzzer/FuzzedDataProvider.h;l=204?q=ConsumeIntegral


    //TODO: Reorder writeData operation so that if we are we want to read something first, it
    // should be at the end of the buffer. We can have a separate buffer which will grow backward
    // and append both buffers while writing the chunk in order to keep this block readable
    // and in sync with fuzzService.

    std::vector<std::byte> buffer;

    // This is always read in fuzzService
    int64_t maybeSetUid = 0; // replace actual uid samples?
    writeData(fd, &maybeSetUid, sizeof(int64_t));

    // Never sed uid in seed corpus
    bool writeUid = false;
    writeData(fd, &writeUid, sizeof(bool));

    // Select to fuzz the services.
    size_t pickInArrayIndex = 0;
    writeData(fd, &pickInArrayIndex, sizeof(size_t));

    // go for reading random code. this will be from recorded transaction
    bool selectCode = true;
    writeData(fd, &selectCode, sizeof(bool));

    uint32_t code = transaction.getCode(); //get from recorded transaction;
    writeData(fd, &code,  sizeof(uint32_t));

    uint32_t flags = transaction.getFlags(); //get from recorded transaction
    writeData(fd, &flags, sizeof(uint32_t));


    size_t extraBindersIndex = 0; //always produce for main binder - make field in reserved bytes?
    writeData(fd, &extraBindersIndex, sizeof(size_t));

    const Parcel& dataParcel =  transaction.getDataParcel();
    // fuzzService selects subdata to be created for filling up rrandom parcel.
    // This should be sum of data sizes from random parcel and all the needed flags in
    // fillRandomParcel
    size_t subDataSize =  dataParcel.dataBufferSize()
                            + 2 * sizeof(bool) //RpcSession, writeHeader internal byte
                            + 2 * sizeof(size_t); // To select index, reading data size in parcel;

    writeData(fd, &subDataSize, sizeof(size_t));

    bool rpcBranch = false; //dont take rpc path
    writeData(fd, &rpcBranch, sizeof(bool));


    bool writeHeaderInternal = true; // always write interface Descriptor

    // implicit branch options->writeHeader(p, provider);
    writeData(fd, &writeHeaderInternal, sizeof(bool));

    size_t fillFuncIndex = 0; // write data function
    writeData(fd, &fillFuncIndex, sizeof(size_t));// pick index, 1 for now

    size_t toWrite = transaction.getDataParcel().dataSize();
    //CHECK(toWrite != 0);

    // Write parcel data size from recorded transaction
    writeData(fd, &toWrite, sizeof(size_t));

    // Write parcel data with size towrite from recorded transaction
    writeData(fd, dataParcel.data(), toWrite);
}

} // namespace android
