#include <gtest/gtest.h>
#include <cutils/properties.h>

enum Mode {
   NORMAL = 0,
   DATA_INJECTION = 1,
   RESTRICTED = 2
};

TEST(SensorServiceCTSTest, PropertySetupCheck) {
    char value[PROPERTY_VALUE_MAX];
    property_get("sys.sensor.mode", value, std::to_string(NORMAL).c_str());
    int res = atoi(value);
    ASSERT_EQ(RESTRICTED, res);
}
