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

#include <android-base/unique_fd.h>
#include <binder/Binder.h>
#include <binder/BpBinder.h>
#include <binder/IBinder.h>
#include <gtest/gtest.h>
#include <string>
#include <fuzzer/FuzzedDataProvider.h>
#include <fuzzseeds/random_parcel_seeds.h>

using namespace android;

// Data copied from FuzzedDataProviderUnittest.cpp
const uint8_t Data[] =
        {0xE2, 0x4B, 0x20, 0x9F, 0x50, 0xB3, 0x56, 0xED, 0xDE, 0x39, 0xD8, 0x75, 0x64, 0x45, 0x54,
         0xE5, 0x34, 0x57, 0x8C, 0x3B, 0xF2, 0x0E, 0x94, 0x1B, 0x10, 0xA2, 0xA2, 0x38, 0x76, 0x21,
         0x8E, 0x2A, 0x57, 0x64, 0x58, 0x0A, 0x27, 0x6D, 0x4C, 0xD0, 0xB5, 0xC1, 0xFC, 0x75, 0xD0,
         0x01, 0x86, 0x66, 0xA8, 0xF1, 0x98, 0x58, 0xFB, 0xFC, 0x64, 0xD2, 0x31, 0x77, 0xAD, 0x0E,
         0x46, 0x87, 0xCC, 0x9B, 0x86, 0x90, 0xFF, 0xB6, 0x64, 0x35, 0xA5, 0x5D, 0x9E, 0x44, 0x51,
         0x87, 0x9E, 0x1E, 0xEE, 0xF3, 0x3B, 0x5C, 0xDD, 0x94, 0x03, 0xAA, 0x18, 0x2C, 0xB7, 0xC4,
         0x37, 0xD5, 0x53, 0x28, 0x60, 0xEF, 0x77, 0xEF, 0x3B, 0x9E, 0xD2, 0xCE, 0xE9, 0x53, 0x2D,
         0xF5, 0x19, 0x7E, 0xBB, 0xB5, 0x46, 0xE2, 0xF7, 0xD6, 0x4D, 0x6D, 0x5B, 0x81, 0x56, 0x6B,
         0x12, 0x55, 0x63, 0xC3, 0xAB, 0x08, 0xBB, 0x2E, 0xD5, 0x11, 0xBC, 0x18, 0xCB, 0x8B, 0x12,
         0x2E, 0x3E, 0x75, 0x32, 0x98, 0x8A, 0xDE, 0x3C, 0xEA, 0x33, 0x46, 0xE7, 0x7A, 0xA5, 0x12,
         0x09, 0x26, 0x7E, 0x7E, 0x03, 0x4F, 0xFD, 0xC0, 0xFD, 0xEA, 0x4F, 0x83, 0x85, 0x39, 0x62,
         0xFB, 0xA2, 0x33, 0xD9, 0x2D, 0xB1, 0x30, 0x6F, 0x88, 0xAB, 0x61, 0xCB, 0x32, 0xEB, 0x30,
         0x3A, 0x11, 0x4D, 0xFD, 0x54, 0xD6, 0x3D, 0x42, 0x73, 0x39, 0x16, 0xCF, 0x3D, 0x29, 0x4A};

class FuzzedDataReversalTest : public ::testing::Test {
public:
    template <typename T>
    void reverseBytes() {
        uint8_t reversedData[100] = {0};
        size_t len = 100;

        // Use fuzzedDataProvider to get int from it
        FuzzedDataProvider provider(Data, sizeof(Data));
        auto totalBytes = provider.remaining_bytes();
        //auto val = provider.ConsumeIntegralInRange<T>(100, 200);

        uint32_t val = provider.ConsumeBool() ? provider.ConsumeIntegral<uint32_t>()
                                               : provider.ConsumeIntegralInRange<uint32_t>(0, 100); // 5
        // Consume integral always takes bytes from end of the data
        // Check how many bytes were consumed and what were those bytes
        auto bytesConsumed = totalBytes - provider.remaining_bytes();
        std::cout << "bytesConsumed : " << bytesConsumed << std::endl;

        // Use the int with reverse api to get the byte
        getReversedBytes(reversedData, len, (T)100,
                         (T)200, val);

        // Compare consume bytes and reversed bytes
        std::cout << "Reversed data " << HexString(reversedData, len) << std::endl;

        FuzzedDataProvider reversedDataProvider(reversedData, len);
        auto reversed = reversedDataProvider.ConsumeIntegralInRange<T>(100, 200);
        std::cout << "Val from reversed data " << reversed << std::endl;
        CHECK(val == reversed);
    }
};

TEST_F(FuzzedDataReversalTest, ReverseBytesFromInt64) {
    reverseBytes<int64_t>();
}

TEST_F(FuzzedDataReversalTest, ReverseBytesFromUInt32) {
    reverseBytes<uint32_t>();
}

TEST_F(FuzzedDataReversalTest, ReverseBytesFromSizeT) {
    reverseBytes<size_t>();
}

TEST_F(FuzzedDataReversalTest, ReverseBytesFromInt32) {
    reverseBytes<int32_t>();
}

TEST_F(FuzzedDataReversalTest, ReverseBytesFromInt32) {
    reverseBytes<uint8_t>();
}

TEST_F(FuzzedDataReversalTest, ReversedDataBuffer) {
    // Use fuzzedDataProvider to get int from it
    FuzzedDataProvider provider(Data, sizeof(Data));
    auto totalBytes = provider.remaining_bytes();

    auto firstVal = provider.ConsumeIntegralInRange<int64_t>(100, 20000);
    auto secondVal = provider.ConsumeIntegral<uint32_t>();
    auto sizeVal = provider.ConsumeIntegralInRange<size_t>(0, 0);
    auto firstFlag =  provider.ConsumeBool();
    auto secondFlag =  provider.ConsumeBool();
    auto thirdVal = provider.ConsumeIntegralInRange<uint64_t>(60000, 650000);
    auto fourthVal = provider.ConsumeIntegralInRange<size_t>(1127, 21321);
    auto thirdFlag =  provider.ConsumeBool();

    auto fifthVal = provider.ConsumeIntegralInRange<int64_t>(static_cast<int64_t>(AID_ROOT) << 32,
                                                             static_cast<int64_t>(AID_USER) << 32);
    int64_t fourthUid = provider.ConsumeIntegral<int64_t>();

    // Consume integral always takes bytes from end of the data
    // Check how many bytes were consumed and what were those bytes
    auto bytesConsumed = totalBytes - provider.remaining_bytes();
    std::cout << "bytesConsumed : " << bytesConsumed << std::endl;

    std::vector<std::byte> integralBuffer;
    writeInBuffer(integralBuffer, static_cast<int64_t>(100), static_cast<int64_t>(20000), firstVal);
    writeInBuffer(integralBuffer, secondVal);
    writeInBuffer(integralBuffer, static_cast<size_t>(0), static_cast<size_t>(0), sizeVal);
    writeInBuffer(integralBuffer, firstFlag);

    std::string msg;
    size_t index = 2000;
    auto functionToCall = provider.PickValueInArray<const std::function<void()>>({
            [&]() {
                msg = "function_0";
                index = 0;
            },
            [&]() {
                msg = "function_1";
                index = 1;
            },
            [&]() {
                msg = "function_2";
                index = 2;
            },
    });
    functionToCall();
    std::cout << "msg :" << msg <<std::endl;
    writeInBuffer(integralBuffer, static_cast<size_t>(0), static_cast<size_t>(2), index);
    writeInBuffer(integralBuffer, secondFlag);
    writeInBuffer(integralBuffer, static_cast<uint64_t>(60000), static_cast<uint64_t>(650000), thirdVal);
    writeInBuffer(integralBuffer, static_cast<size_t>(1127), static_cast<size_t>(21321), fourthVal);
    writeInBuffer(integralBuffer, thirdFlag);

    const uint8_t* byteDataReversed =  reinterpret_cast<const uint8_t*>(integralBuffer.data());
    FuzzedDataProvider reversedProvider(byteDataReversed, integralBuffer.size());
    std::cout << "Buffer size : " << integralBuffer.size() << std::endl;

    CHECK(firstVal == reversedProvider.ConsumeIntegralInRange<int64_t>(100, 20000));
    CHECK(secondVal == reversedProvider.ConsumeIntegral<uint32_t>());
    CHECK(sizeVal ==  reversedProvider.ConsumeIntegralInRange<size_t>(0, 0));
    CHECK(firstFlag == reversedProvider.ConsumeBool());

    std::string reversedMsg;
    size_t reversedIndex = 1000;
    auto reversedFunctionToCall = reversedProvider.PickValueInArray<const std::function<void()>>({
            [&]() {
                reversedMsg = "function_0";
                reversedIndex = 0;
            },
            [&]() {
                reversedMsg = "function_1";
                reversedIndex = 1;
            },
            [&]() {
                reversedMsg = "function_2";
                reversedIndex = 2;
            },
    });
    reversedFunctionToCall();
    std::cout << "reversedMsg :" << reversedMsg <<std::endl;
    CHECK(reversedMsg == msg && reversedIndex == index);

    CHECK(secondFlag == reversedProvider.ConsumeBool());
    CHECK(thirdVal == reversedProvider.ConsumeIntegralInRange<uint64_t>(60000, 650000));
    CHECK(fourthVal == reversedProvider.ConsumeIntegralInRange<size_t>(1127, 21321));
    CHECK(thirdFlag == reversedProvider.ConsumeBool());
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

    return RUN_ALL_TESTS();
}
