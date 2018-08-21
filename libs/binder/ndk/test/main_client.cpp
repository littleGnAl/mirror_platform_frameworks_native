/*
 * Copyright (C) 2018 The Android Open Source Project
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
#include <gtest/gtest.h>
#include <iface/iface.h>

using ::android::sp;

TEST(Client, DoubleNumber) {
    // FIXME: sometimes this takes 1s because of the getService timeout
    sp<IFoo> foo = IFoo::getService(IFoo::kSomeInstanceName);
    ASSERT_NE(foo, nullptr);
    EXPECT_EQ(2, foo->doubleNumber(1));
}

TEST(Client, GetServiceInProcess) {
    class MyTestFoo : public IFoo {
        int32_t doubleNumber(int32_t in) override {
            LOG(INFO) << "doubleNumber " << in;
            return 2 * in;
        }
    };

    static const char* kInstanceName = "test-get-service-in-process";

    sp<IFoo> foo = new MyTestFoo;
    EXPECT_EQ(EX_NONE, foo->registerAsService(kInstanceName));

    sp<IFoo> getFoo = IFoo::getService(kInstanceName);
    EXPECT_EQ(foo.get(), getFoo.get());
}
