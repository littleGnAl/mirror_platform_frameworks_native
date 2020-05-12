
#ifndef FUZZ_TOUCHINPUTMAPPERHELPERS_H
#define FUZZ_TOUCHINPUTMAPPERHELPERS_H

namespace android {

class TouchInputMapperTest : public InputMapperTest {
public:
    int32_t DEVICE_ID;
    static const int32_t RAW_X_MIN;
    static const int32_t RAW_X_MAX;
    static const int32_t RAW_Y_MIN;
    static const int32_t RAW_Y_MAX;
    static const int32_t RAW_TOUCH_MIN;
    static const int32_t RAW_TOUCH_MAX;
    static const int32_t RAW_TOOL_MIN;
    static const int32_t RAW_TOOL_MAX;
    static const int32_t RAW_PRESSURE_MIN;
    static const int32_t RAW_PRESSURE_MAX;
    static const int32_t RAW_ORIENTATION_MIN;
    static const int32_t RAW_ORIENTATION_MAX;
    static const int32_t RAW_DISTANCE_MIN;
    static const int32_t RAW_DISTANCE_MAX;
    static const int32_t RAW_TILT_MIN;
    static const int32_t RAW_TILT_MAX;
    static const int32_t RAW_ID_MIN;
    static const int32_t RAW_ID_MAX;
    static const int32_t RAW_SLOT_MIN;
    static const int32_t RAW_SLOT_MAX;
    static const float X_PRECISION;
    static const float Y_PRECISION;
    static const float X_PRECISION_VIRTUAL;
    static const float Y_PRECISION_VIRTUAL;
    static const float GEOMETRIC_SCALE;
    static const TouchAffineTransformation AFFINE_TRANSFORM;
    static const VirtualKeyDefinition VIRTUAL_KEYS[2];
    const std::string UNIQUE_ID = "local:0";
    const std::string SECONDARY_UNIQUE_ID = "local:1";
    enum Axes {
        POSITION = 1 << 0,
        TOUCH = 1 << 1,
        TOOL = 1 << 2,
        PRESSURE = 1 << 3,
        ORIENTATION = 1 << 4,
        MINOR = 1 << 5,
        ID = 1 << 6,
        DISTANCE = 1 << 7,
        TILT = 1 << 8,
        SLOT = 1 << 9,
        TOOL_TYPE = 1 << 10,
    };
    void prepareDisplay(int32_t orientation, std::optional<uint8_t> port = NO_PORT);
    void prepareSecondaryDisplay(ViewportType type, std::optional<uint8_t> port = NO_PORT);
    void prepareVirtualDisplay(int32_t orientation);
    void prepareVirtualKeys();
    void prepareLocationCalibration();
    int32_t toRawX(float displayX);
    int32_t toRawY(float displayY);
    float toCookedX(float rawX, float rawY);
    float toCookedY(float rawX, float rawY);
    float toDisplayX(int32_t rawX);
    float toDisplayX(int32_t rawX, int32_t displayWidth);
    float toDisplayY(int32_t rawY);
    float toDisplayY(int32_t rawY, int32_t displayHeight);
};
const int32_t TouchInputMapperTest::RAW_X_MIN = 25;
const int32_t TouchInputMapperTest::RAW_X_MAX = 1019;
const int32_t TouchInputMapperTest::RAW_Y_MIN = 30;
const int32_t TouchInputMapperTest::RAW_Y_MAX = 1009;
const int32_t TouchInputMapperTest::RAW_TOUCH_MIN = 0;
const int32_t TouchInputMapperTest::RAW_TOUCH_MAX = 31;
const int32_t TouchInputMapperTest::RAW_TOOL_MIN = 0;
const int32_t TouchInputMapperTest::RAW_TOOL_MAX = 15;
const int32_t TouchInputMapperTest::RAW_PRESSURE_MIN = 0;
const int32_t TouchInputMapperTest::RAW_PRESSURE_MAX = 255;
const int32_t TouchInputMapperTest::RAW_ORIENTATION_MIN = -7;
const int32_t TouchInputMapperTest::RAW_ORIENTATION_MAX = 7;
const int32_t TouchInputMapperTest::RAW_DISTANCE_MIN = 0;
const int32_t TouchInputMapperTest::RAW_DISTANCE_MAX = 7;
const int32_t TouchInputMapperTest::RAW_TILT_MIN = 0;
const int32_t TouchInputMapperTest::RAW_TILT_MAX = 150;
const int32_t TouchInputMapperTest::RAW_ID_MIN = 0;
const int32_t TouchInputMapperTest::RAW_ID_MAX = 9;
const int32_t TouchInputMapperTest::RAW_SLOT_MIN = 0;
const int32_t TouchInputMapperTest::RAW_SLOT_MAX = 9;
const float TouchInputMapperTest::X_PRECISION = float(RAW_X_MAX - RAW_X_MIN + 1) / DISPLAY_WIDTH;
const float TouchInputMapperTest::Y_PRECISION = float(RAW_Y_MAX - RAW_Y_MIN + 1) / DISPLAY_HEIGHT;
const float TouchInputMapperTest::X_PRECISION_VIRTUAL =
        float(RAW_X_MAX - RAW_X_MIN + 1) / VIRTUAL_DISPLAY_WIDTH;
const float TouchInputMapperTest::Y_PRECISION_VIRTUAL =
        float(RAW_Y_MAX - RAW_Y_MIN + 1) / VIRTUAL_DISPLAY_HEIGHT;
const TouchAffineTransformation TouchInputMapperTest::AFFINE_TRANSFORM =
        TouchAffineTransformation(1, -2, 3, -4, 5, -6);
const float TouchInputMapperTest::GEOMETRIC_SCALE =
        avg(float(DISPLAY_WIDTH) / (RAW_X_MAX - RAW_X_MIN + 1),
            float(DISPLAY_HEIGHT) / (RAW_Y_MAX - RAW_Y_MIN + 1));
const VirtualKeyDefinition TouchInputMapperTest::VIRTUAL_KEYS[2] = {
        {KEY_HOME, 60, DISPLAY_HEIGHT + 15, 20, 20},
        {KEY_MENU, DISPLAY_HEIGHT - 60, DISPLAY_WIDTH + 15, 20, 20},
};
void TouchInputMapperTest::prepareDisplay(int32_t orientation, std::optional<uint8_t> port) {
    setDisplayInfoAndReconfigure(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, orientation, UNIQUE_ID,
                                 port, ViewportType::VIEWPORT_INTERNAL);
}
void TouchInputMapperTest::prepareSecondaryDisplay(ViewportType type, std::optional<uint8_t> port) {
    setDisplayInfoAndReconfigure(SECONDARY_DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT,
                                 DISPLAY_ORIENTATION_0, SECONDARY_UNIQUE_ID, port, type);
}
void TouchInputMapperTest::prepareVirtualDisplay(int32_t orientation) {
    setDisplayInfoAndReconfigure(VIRTUAL_DISPLAY_ID, VIRTUAL_DISPLAY_WIDTH, VIRTUAL_DISPLAY_HEIGHT,
                                 orientation, VIRTUAL_DISPLAY_UNIQUE_ID, NO_PORT,
                                 ViewportType::VIEWPORT_VIRTUAL);
}
void TouchInputMapperTest::prepareVirtualKeys() {
    mFakeEventHub->addVirtualKeyDefinition(DEVICE_ID, VIRTUAL_KEYS[0]);
    mFakeEventHub->addVirtualKeyDefinition(DEVICE_ID, VIRTUAL_KEYS[1]);
    mFakeEventHub->addKey(DEVICE_ID, KEY_HOME, 0, AKEYCODE_HOME, POLICY_FLAG_WAKE);
    mFakeEventHub->addKey(DEVICE_ID, KEY_MENU, 0, AKEYCODE_MENU, POLICY_FLAG_WAKE);
}
void TouchInputMapperTest::prepareLocationCalibration() {
    mFakePolicy->setTouchAffineTransformation(AFFINE_TRANSFORM);
}
int32_t TouchInputMapperTest::toRawX(float displayX) {
    return int32_t(displayX * (RAW_X_MAX - RAW_X_MIN + 1) / DISPLAY_WIDTH + RAW_X_MIN);
}
int32_t TouchInputMapperTest::toRawY(float displayY) {
    return int32_t(displayY * (RAW_Y_MAX - RAW_Y_MIN + 1) / DISPLAY_HEIGHT + RAW_Y_MIN);
}
float TouchInputMapperTest::toCookedX(float rawX, float rawY) {
    AFFINE_TRANSFORM.applyTo(rawX, rawY);
    return rawX;
}
float TouchInputMapperTest::toCookedY(float rawX, float rawY) {
    AFFINE_TRANSFORM.applyTo(rawX, rawY);
    return rawY;
}
float TouchInputMapperTest::toDisplayX(int32_t rawX) {
    return toDisplayX(rawX, DISPLAY_WIDTH);
}
float TouchInputMapperTest::toDisplayX(int32_t rawX, int32_t displayWidth) {
    return float(rawX - RAW_X_MIN) * displayWidth / (RAW_X_MAX - RAW_X_MIN + 1);
}
float TouchInputMapperTest::toDisplayY(int32_t rawY) {
    return toDisplayY(rawY, DISPLAY_HEIGHT);
}
float TouchInputMapperTest::toDisplayY(int32_t rawY, int32_t displayHeight) {
    return float(rawY - RAW_Y_MIN) * displayHeight / (RAW_Y_MAX - RAW_Y_MIN + 1);
}
} // namespace android

#endif // FUZZ_TOUCHINPUTMAPPERHELPERS_H
