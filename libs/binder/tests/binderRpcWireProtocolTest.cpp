/*
 * Copyright (C) 2021 The Android Open Source Project
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

#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/strings.h>
#include <binder/Parcel.h>
#include <binder/RpcSession.h>
#include <gtest/gtest.h>

#include "../Debug.h"

using android::BBinder;
using android::IBinder;
using android::OK;
using android::Parcel;
using android::Parcelable;
using android::RpcSession;
using android::sp;
using android::status_t;
using android::String16;
using android::String8;

// FIXME: plan/setup tests for FDs?
// FIXME: plan/setup tests for flattenable
// FIXME: plan/setup tests for 'Status'
// FIXME: plan/setup tests for other 'built-in' parcelable objects
// (ParcelFileDescriptor)

static const int32_t kInt32Array[] = {-1, 0, 17};
static const uint8_t kByteArray[] = {0, 17, 255};
enum EnumInt8 : int8_t { Int8A, Int8B };
enum EnumInt32 : int32_t { Int32A, Int32B };
enum EnumInt64 : int64_t { Int64A, Int64B };
struct AParcelable : Parcelable {
    status_t writeToParcel(Parcel* parcel) const { return parcel->writeInt32(37); }
    status_t readFromParcel(const Parcel*) { return OK; }
};

// clang-format off
constexpr size_t kFillFunIndexLineBase = __LINE__ + 2;
static const std::vector<std::function<void(Parcel* p)>> kFillFuns {
    [](Parcel* p) { ASSERT_EQ(OK, p->writeInterfaceToken(String16(u"tok"))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeInt32(-1)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeInt32(0)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeInt32(17)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUint32(0)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUint32(1)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUint32(10003)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeInt64(-1)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeInt64(0)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeInt64(17)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUint64(0)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUint64(1)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUint64(10003)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeFloat(0.0f)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeFloat(0.1f)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeFloat(9.1f)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeDouble(0.0)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeDouble(0.1)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeDouble(9.1)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeCString("")); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeCString("a")); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeCString("baba")); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeString8(String8(""))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeString8(String8("a"))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeString8(String8("baba"))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeString16(String16(u""))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeString16(String16(u"a"))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeString16(String16(u"baba"))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeStrongBinder(nullptr)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeInt32Array(arraysize(kInt32Array), kInt32Array)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeByteArray(arraysize(kByteArray), kByteArray)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeBool(true)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeBool(false)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeChar('a')); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeChar('?')); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeChar('\0')); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeByte(-128)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeByte(0)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeByte(127)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUtf8AsUtf16(std::string(""))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUtf8AsUtf16(std::string("a"))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUtf8AsUtf16(std::string("abab"))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUtf8AsUtf16(std::nullopt)); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUtf8AsUtf16(std::optional<std::string>(""))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUtf8AsUtf16(std::optional<std::string>("a"))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUtf8AsUtf16(std::optional<std::string>("abab"))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeByteVector(std::optional<std::vector<int8_t>>(std::nullopt))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeByteVector(std::optional<std::vector<int8_t>>({-1, 0, 17}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeByteVector(std::vector<int8_t>({}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeByteVector(std::vector<int8_t>({-1, 0, 17}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeByteVector(std::optional<std::vector<uint8_t>>(std::nullopt))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeByteVector(std::optional<std::vector<uint8_t>>({0, 1, 17}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeByteVector(std::vector<uint8_t>({}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeByteVector(std::vector<uint8_t>({0, 1, 17}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeInt32Vector(std::optional<std::vector<int32_t>>(std::nullopt))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeInt32Vector(std::optional<std::vector<int32_t>>({-1, 0, 17}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeInt32Vector(std::vector<int32_t>({}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeInt32Vector(std::vector<int32_t>({-1, 0, 17}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeInt64Vector(std::optional<std::vector<int64_t>>(std::nullopt))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeInt64Vector(std::optional<std::vector<int64_t>>({-1, 0, 17}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeInt64Vector(std::vector<int64_t>({}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeInt64Vector(std::vector<int64_t>({-1, 0, 17}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUint64Vector(std::optional<std::vector<uint64_t>>(std::nullopt))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUint64Vector(std::optional<std::vector<uint64_t>>({0, 1, 17}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUint64Vector(std::vector<uint64_t>({}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUint64Vector(std::vector<uint64_t>({0, 1, 17}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeFloatVector(std::optional<std::vector<float>>(std::nullopt))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeFloatVector(std::optional<std::vector<float>>({0.0f, 0.1f, 9.1f}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeFloatVector(std::vector<float>({}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeFloatVector(std::vector<float>({0.0f, 0.1f, 9.1f}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeDoubleVector(std::optional<std::vector<double>>(std::nullopt))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeDoubleVector(std::optional<std::vector<double>>({0.0, 0.1, 9.1}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeDoubleVector(std::vector<double>({}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeDoubleVector(std::vector<double>({0.0, 0.1, 9.1}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeBoolVector(std::optional<std::vector<bool>>(std::nullopt))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeBoolVector(std::optional<std::vector<bool>>({true, false}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeBoolVector(std::vector<bool>({}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeBoolVector(std::vector<bool>({true, false}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeCharVector(std::optional<std::vector<char16_t>>(std::nullopt))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeCharVector(std::optional<std::vector<char16_t>>({'a', '\0', '?'}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeCharVector(std::vector<char16_t>({}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeCharVector(std::vector<char16_t>({'a', '\0', '?'}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeString16Vector(std::optional<std::vector<std::optional<String16>>>(std::nullopt))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeString16Vector(std::optional<std::vector<std::optional<String16>>>({std::nullopt, String16(), String16(u"a")}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeString16Vector(std::vector<std::optional<String16>>({}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeString16Vector(std::vector<std::optional<String16>>({std::nullopt, String16(), String16(u"a")}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUtf8VectorAsUtf16Vector(std::optional<std::vector<std::optional<std::string>>>(std::nullopt))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUtf8VectorAsUtf16Vector(std::optional<std::vector<std::optional<std::string>>>({std::nullopt, std::string(), std::string("a")}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUtf8VectorAsUtf16Vector(std::vector<std::optional<std::string>>({}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeUtf8VectorAsUtf16Vector(std::vector<std::optional<std::string>>({std::nullopt, std::string(), std::string("a")}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeStrongBinderVector(std::optional<std::vector<sp<IBinder>>>(std::nullopt))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeStrongBinderVector(std::optional<std::vector<sp<IBinder>>>({nullptr}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeStrongBinderVector(std::vector<sp<IBinder>>({}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeStrongBinderVector(std::vector<sp<IBinder>>({nullptr}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeEnumVector(std::optional<std::vector<EnumInt8>>(std::nullopt))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeEnumVector(std::optional<std::vector<EnumInt8>>({Int8A, Int8B}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeEnumVector(std::vector<EnumInt8>({Int8A, Int8B}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeEnumVector(std::optional<std::vector<EnumInt32>>(std::nullopt))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeEnumVector(std::optional<std::vector<EnumInt32>>({Int32A, Int32B}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeEnumVector(std::vector<EnumInt32>({Int32A, Int32B}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeEnumVector(std::optional<std::vector<EnumInt64>>(std::nullopt))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeEnumVector(std::optional<std::vector<EnumInt64>>({Int64A, Int64B}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeEnumVector(std::vector<EnumInt64>({Int64A, Int64B}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeParcelableVector(std::optional<std::vector<std::optional<AParcelable>>>(std::nullopt))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeParcelableVector(std::optional<std::vector<std::optional<AParcelable>>>({AParcelable()}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeParcelableVector(std::vector<AParcelable>({AParcelable()}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeNullableParcelable(std::optional<AParcelable>(std::nullopt))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeNullableParcelable(std::optional<AParcelable>(AParcelable()))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeParcelable(AParcelable())); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeVectorSize(std::vector<int32_t>({0, 1, 17}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeVectorSize(std::vector<AParcelable>({}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeVectorSize(std::optional<std::vector<int32_t>>(std::nullopt))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeVectorSize(std::optional<std::vector<int32_t>>({0, 1, 17}))); },
    [](Parcel* p) { ASSERT_EQ(OK, p->writeNoException()); },
};
// clang-format on

static void setParcelForRpc(Parcel* p) {
    auto session = sp<RpcSession>::make();
    CHECK(session->addNullDebuggingClient());
    p->markForRpc(session);
}

std::string buildRepr() {
    std::string result;
    for (size_t i = 0; i < kFillFuns.size(); i++) {
        if (i != 0) result += "|";
        Parcel p;
        setParcelForRpc(&p);
        kFillFuns[i](&p);

        result += android::hexString(p.data(), p.dataSize());
    }
    return result;
}

const std::string kCurrentRepr =
        "0300000074006f006b000000|ffffffff|00000000|11000000|00000000|01000000|13270000|"
        "ffffffffffffffff|0000000000000000|1100000000000000|0000000000000000|0100000000000000|"
        "1327000000000000|00000000|cdcccc3d|9a991141|0000000000000000|9a9999999999b93f|"
        "3333333333332240|00000000|61000000|6261626100000000|0000000000000000|0100000061000000|"
        "040000006261626100000000|0000000000000000|0100000061000000|"
        "04000000620061006200610000000000|0000000001000000|03000000ffffffff0000000011000000|"
        "030000000011ff00|01000000|00000000|61000000|3f000000|00000000|80ffffff|00000000|7f000000|"
        "0000000000000000|0100000061000000|04000000610062006100620000000000|ffffffff|"
        "0000000000000000|0100000061000000|04000000610062006100620000000000|ffffffff|"
        "03000000ff001100|00000000|03000000ff001100|ffffffff|0300000000011100|00000000|"
        "0300000000011100|ffffffff|03000000ffffffff0000000011000000|00000000|"
        "03000000ffffffff0000000011000000|ffffffff|"
        "03000000ffffffffffffffff00000000000000001100000000000000|00000000|"
        "03000000ffffffffffffffff00000000000000001100000000000000|ffffffff|"
        "03000000000000000000000001000000000000001100000000000000|00000000|"
        "03000000000000000000000001000000000000001100000000000000|ffffffff|"
        "0300000000000000cdcccc3d9a991141|00000000|0300000000000000cdcccc3d9a991141|ffffffff|"
        "0300000000000000000000009a9999999999b93f3333333333332240|00000000|"
        "0300000000000000000000009a9999999999b93f3333333333332240|ffffffff|"
        "020000000100000000000000|00000000|020000000100000000000000|ffffffff|"
        "0300000061000000000000003f000000|00000000|0300000061000000000000003f000000|ffffffff|"
        "03000000ffffffff00000000000000000100000061000000|00000000|"
        "03000000ffffffff00000000000000000100000061000000|ffffffff|"
        "03000000ffffffff00000000000000000100000061000000|00000000|"
        "03000000ffffffff00000000000000000100000061000000|ffffffff|010000000000000001000000|"
        "00000000|010000000000000001000000|ffffffff|0200000000010000|0200000000010000|ffffffff|"
        "020000000000000001000000|020000000000000001000000|ffffffff|"
        "0200000000000000000000000100000000000000|0200000000000000000000000100000000000000|"
        "ffffffff|010000000100000025000000|010000000100000025000000|00000000|0100000025000000|"
        "0100000025000000|03000000|00000000|ffffffff|03000000|00000000";

TEST(RpcWire, CurrentVersion) {
    auto repr = android::base::Split(kCurrentRepr, "|");

    ASSERT_EQ(repr.size(), kFillFuns.size());

    for (size_t i = 0; i < kFillFuns.size(); i++) {
        Parcel p;
        setParcelForRpc(&p);
        kFillFuns[i](&p);

        EXPECT_EQ(repr[i], android::hexString(p.data(), p.dataSize()))
                << "Format mismatch, see " __FILE__ " line " << (kFillFunIndexLineBase + i);
    }
}
