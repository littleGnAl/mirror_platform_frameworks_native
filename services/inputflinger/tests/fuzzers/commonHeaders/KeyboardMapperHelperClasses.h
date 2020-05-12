
#ifndef FUZZ_KEYBOARDMAPPERHELPERS_H
#define FUZZ_KEYBOARDMAPPERHELPERS_H

#include "InputMapperTest.h"

namespace android {

class KeyboardInputMapperTest : public InputMapperTest {
    // make test easy
public:
    const std::string UNIQUE_ID = "local:0";
    void prepareDisplay(int32_t orientation);
    void testDPadKeyRotation(KeyboardInputMapper* mapper, int32_t originalScanCode,
                             int32_t originalKeyCode, int32_t rotatedKeyCode);
    virtual ~KeyboardInputMapperTest() {}
};
/* Similar to setDisplayInfoAndReconfigure, but pre-populates all parameters except for the
 * orientation.
 */
void KeyboardInputMapperTest::prepareDisplay(int32_t orientation) {
    setDisplayInfoAndReconfigure(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, orientation, UNIQUE_ID,
                                 NO_PORT, ViewportType::VIEWPORT_INTERNAL);
}
void KeyboardInputMapperTest::testDPadKeyRotation(KeyboardInputMapper* mapper,
                                                  int32_t originalScanCode, int32_t originalKeyCode,
                                                  int32_t rotatedKeyCode) {
    NotifyKeyArgs args;
    InputMapperTest::process(mapper, ARBITRARY_TIME, EV_KEY, originalScanCode, 1);
    /*ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(AKEY_EVENT_ACTION_DOWN, args.action);
    ASSERT_EQ(originalScanCode, args.scanCode);
    ASSERT_EQ(rotatedKeyCode, args.keyCode);*/
    InputMapperTest::process(mapper, ARBITRARY_TIME, EV_KEY, originalScanCode, 0);
    /*ASSERT_NO_FATAL_FAILURE(mFakeListener->assertNotifyKeyWasCalled(&args));
    ASSERT_EQ(AKEY_EVENT_ACTION_UP, args.action);
    ASSERT_EQ(originalScanCode, args.scanCode);
    ASSERT_EQ(rotatedKeyCode, args.keyCode);*/
}
} // namespace android

#endif // FUZZ_KEYBOARDMAPPERHELPERS_H
