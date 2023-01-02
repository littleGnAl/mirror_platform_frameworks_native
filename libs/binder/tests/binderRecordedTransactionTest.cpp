/*
 * Copyright (C) 2022 The Android Open Source Project
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

#include <binder/BinderRecordReplay.h>
#include <gtest/gtest.h>

using android::Parcel;
using android::status_t;
using android::base::unique_fd;
using android::binder::debug::RecordedTransaction;

TEST(BinderRecordedTransaction, RoundTripEncoding) {
    Parcel d;
    d.writeInt32(12);
    Parcel r;
    r.writeInt32(99);
    auto transaction = RecordedTransaction::fromDetails(1, 42, d, r, 0);

    auto file = std::tmpfile();
    auto fd = unique_fd(dup(fileno(file)));

    status_t status = transaction->dumpToFile(fd);
    ASSERT_EQ(android::NO_ERROR, status);

    std::rewind(file);

    auto retrievedTransaction = RecordedTransaction::fromFile(fd);

    EXPECT_EQ(transaction->getCode(), retrievedTransaction->getCode());
    EXPECT_EQ(transaction->getFlags(), retrievedTransaction->getFlags());
    EXPECT_EQ(transaction->getDataSize(), retrievedTransaction->getDataSize());
    EXPECT_EQ(transaction->getReplySize(), retrievedTransaction->getReplySize());
    EXPECT_EQ(transaction->getReturnedStatus(), retrievedTransaction->getReturnedStatus());
    EXPECT_EQ(transaction->getVersion(), retrievedTransaction->getVersion());

    EXPECT_EQ(retrievedTransaction->getDataParcel().readInt32(), 12);
    EXPECT_EQ(retrievedTransaction->getReplyParcel().readInt32(), 99);
}
