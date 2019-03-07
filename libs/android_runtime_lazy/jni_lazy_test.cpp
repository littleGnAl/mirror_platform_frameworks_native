#include <gtest/gtest.h>

#include "jni_lazy.h"

TEST(MyTest, First) {
    EXPECT_EQ(nullptr, ::android::lazy::getJNIEnv());
}
