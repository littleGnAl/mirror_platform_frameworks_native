
#ifndef FUZZ_CURSORMAPPERHELPERS_H
#define FUZZ_CURSORMAPPERHELPERS_H

#include <fuzzer/FuzzedDataProvider.h>
#include "InputMapperTest.h"

namespace android {
class CursorInputMapperTest : public InputMapperTest {
public:
    static const int32_t TRACKBALL_MOVEMENT_THRESHOLD;
    std::shared_ptr<FakePointerController> mFakePointerController;

    virtual void SetUp(FuzzedDataProvider* tester) {
        InputMapperTest::SetUp(tester);
        mFakePointerController = std::make_shared<FakePointerController>();
        mFakePolicy->setPointerController(mDevice->getId(), mFakePointerController);
    }

    virtual void TearDown() { InputMapperTest::TearDown(); }

    void testMotionRotation(CursorInputMapper* mapper, int32_t originalX, int32_t originalY,
                            int32_t rotatedX, int32_t rotatedY);

    InputDevice* GetmDevice() { return mDevice; }

    FakeInputReaderContext* GetmFakeContext() { return mFakeContext; }

    std::shared_ptr<FakePointerController> GetmFakePointerController() {
        return mFakePointerController;
    }

    sp<FakeInputReaderPolicy> GetmFakePolicy() { return mFakePolicy; }

    void prepareDisplay(int32_t orientation) {
        const std::string uniqueId = "local:0";
        const ViewportType viewportType = ViewportType::VIEWPORT_INTERNAL;
        setDisplayInfoAndReconfigure(DISPLAY_ID, DISPLAY_WIDTH, DISPLAY_HEIGHT, orientation,
                                     uniqueId, NO_PORT, viewportType);
    }
};

const int32_t CursorInputMapperTest::TRACKBALL_MOVEMENT_THRESHOLD = 6;
void CursorInputMapperTest::testMotionRotation(CursorInputMapper* mapper, int32_t originalX,
                                               int32_t originalY, int32_t rotatedX,
                                               int32_t rotatedY) {
    NotifyMotionArgs args;

    process(mapper, ARBITRARY_TIME, EV_REL, REL_X, originalX);
    process(mapper, ARBITRARY_TIME, EV_REL, REL_Y, originalY);
    process(mapper, ARBITRARY_TIME, EV_SYN, SYN_REPORT, 0);
}
} // namespace android

#endif // FUZZ_CURSORMAPPERHELPERS_H
