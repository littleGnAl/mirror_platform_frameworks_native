#include <iostream>
#include <memory>
#include <vector>

#include "BufferQueueLayer.h"
#include "EffectLayer.h"
#include "Layer.h"
#include "fuzzer/FuzzedDataProvider.h"
#include "renderengine/mock/RenderEngine.h"
#include "tests/unittests/TestableSurfaceFlinger.h"
#include "tests/unittests/mock/DisplayHardware/MockComposer.h"
#include "tests/unittests/mock/DisplayHardware/MockPowerAdvisor.h"
#include "tests/unittests/mock/MockDispSync.h"
#include "tests/unittests/mock/MockEventControlThread.h"
#include "tests/unittests/mock/MockEventThread.h"
#include "tests/unittests/mock/MockMessageQueue.h"
#include "tests/unittests/mock/MockTimeStats.h"
#include "tests/unittests/mock/system/window/MockNativeWindow.h"

using android::Parcel;
using android::sp;
using android::status_t;
using std::vector;

void setupNonPrivCodes(vector<uint32_t>& codes) {
    uint32_t i = 2; // non priv start at [2-43]
    while (i < 43) {
        switch (i) {
            case android::BnSurfaceComposer::CREATE_DISPLAY_EVENT_CONNECTION:
            case android::BnSurfaceComposer::AUTHENTICATE_SURFACE:
            case android::BnSurfaceComposer::GET_ACTIVE_COLOR_MODE:
            case android::BnSurfaceComposer::GET_ACTIVE_CONFIG:
            case android::BnSurfaceComposer::GET_PHYSICAL_DISPLAY_IDS:
            case android::BnSurfaceComposer::GET_PHYSICAL_DISPLAY_TOKEN:
            case android::BnSurfaceComposer::GET_DISPLAY_COLOR_MODES:
            case android::BnSurfaceComposer::GET_DISPLAY_NATIVE_PRIMARIES:
            case android::BnSurfaceComposer::GET_DISPLAY_CONFIGS:
            case android::BnSurfaceComposer::GET_DISPLAY_STATS:
            case android::BnSurfaceComposer::GET_SUPPORTED_FRAME_TIMESTAMPS:
            case android::BnSurfaceComposer::SET_TRANSACTION_STATE:
            case android::BnSurfaceComposer::CREATE_CONNECTION:
            case android::BnSurfaceComposer::GET_COLOR_MANAGEMENT:
            case android::BnSurfaceComposer::GET_COMPOSITION_PREFERENCE:
            case android::BnSurfaceComposer::GET_PROTECTED_CONTENT_SUPPORT:
            case android::BnSurfaceComposer::IS_WIDE_COLOR_DISPLAY:
            case android::BnSurfaceComposer::GET_DISPLAY_BRIGHTNESS_SUPPORT:
            case android::BnSurfaceComposer::SET_DISPLAY_BRIGHTNESS:
                codes.push_back(i++);
                break;
            default:
                ++i;
                break;
        }
    }
}

// TODO: Fix issues with fuzzer exiting on some backdoor codes
void setupBackdoors(vector<uint32_t>& codes) {
    // Numbers from 1000 to 1036 are currently used for backdoors. The code
    // in onTransact verifies that the user is root, and has access to use SF.
    uint32_t i = 1000;
    while (i < 1036) {
        codes.push_back(i);
        ++i;
    }
}

/*
 Method for setting up the priv codes
 TODO: submit bug for CAPTURE_LAYERS
*/
void setupPrivCodes(vector<uint32_t>& codes) {
    uint32_t i = 3; // priv start at [3-43]
    while (i < 43) {
        switch (i) {
            case android::BnSurfaceComposer::BOOT_FINISHED:
            case android::BnSurfaceComposer::CLEAR_ANIMATION_FRAME_STATS:
            case android::BnSurfaceComposer::CREATE_DISPLAY:
            case android::BnSurfaceComposer::DESTROY_DISPLAY:
            case android::BnSurfaceComposer::ENABLE_VSYNC_INJECTIONS:
            case android::BnSurfaceComposer::GET_ANIMATION_FRAME_STATS:
            case android::BnSurfaceComposer::GET_HDR_CAPABILITIES:
            case android::BnSurfaceComposer::SET_DESIRED_DISPLAY_CONFIG_SPECS:
            case android::BnSurfaceComposer::GET_DESIRED_DISPLAY_CONFIG_SPECS:
            case android::BnSurfaceComposer::SET_ACTIVE_COLOR_MODE:
            case android::BnSurfaceComposer::GET_AUTO_LOW_LATENCY_MODE_SUPPORT:
            case android::BnSurfaceComposer::SET_AUTO_LOW_LATENCY_MODE:
            case android::BnSurfaceComposer::GET_GAME_CONTENT_TYPE_SUPPORT:
            case android::BnSurfaceComposer::SET_GAME_CONTENT_TYPE:
            case android::BnSurfaceComposer::INJECT_VSYNC:
            case android::BnSurfaceComposer::SET_POWER_MODE:
            case android::BnSurfaceComposer::GET_DISPLAYED_CONTENT_SAMPLING_ATTRIBUTES:
            case android::BnSurfaceComposer::SET_DISPLAY_CONTENT_SAMPLING_ENABLED:
            case android::BnSurfaceComposer::GET_DISPLAYED_CONTENT_SAMPLE:
            case android::BnSurfaceComposer::NOTIFY_POWER_HINT:
            case android::BnSurfaceComposer::SET_GLOBAL_SHADOW_SETTINGS:
            case android::BnSurfaceComposer::ACQUIRE_FRAME_RATE_FLEXIBILITY_TOKEN:
            case android::BnSurfaceComposer::CAPTURE_LAYERS:
            case android::BnSurfaceComposer::CAPTURE_SCREEN:
            case android::BnSurfaceComposer::ADD_REGION_SAMPLING_LISTENER:
                codes.push_back(i++);
                break;
            default:
                ++i;
                break;
        }
    }
}

void randomizeParcels(Parcel& fuzzed_data, const uint8_t* data, size_t size) {
    int inputNumber = 0;
    sp<android::IBinder> applyToken;
    FuzzedDataProvider fd(data, size);
    uint32_t whichOrder;

    while (inputNumber < 10 && fd.remaining_bytes() > 0) {
        whichOrder = fd.ConsumeIntegralInRange<uint32_t>(0, 10);
        switch (whichOrder) {
            case 0:
            case 1:
            case 2:
            case 3:
                fuzzed_data.writeUint32(fd.ConsumeIntegralInRange<uint32_t>(0, UINT32_MAX));
                inputNumber++;
                break;
            case 4:
            case 5:
                fuzzed_data.writeUint64(fd.ConsumeIntegralInRange<uint64_t>(0, UINT64_MAX));
                inputNumber++;
                break;
            case 6:
            case 7:
                fuzzed_data.writeStrongBinder(applyToken);
                inputNumber++;
                break;
            case 8:
                fuzzed_data.writeInt32(fd.ConsumeIntegralInRange<int32_t>(0, INT32_MAX));
                inputNumber++;
                break;
            case 9:
                fuzzed_data.setData(data, size);
                inputNumber++;
                break;
            default:
                break;
        }
    }
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    if (size < 25) {
        return 0;
    }

    FuzzedDataProvider fdp(data, size);
    android::TestableSurfaceFlinger SFfuzz;
    vector<uint32_t> composerCodes;
    Parcel fuzzed_data, reply;

    // creating mock components for surface flinger
    android::mock::MessageQueue* mMessageQueue = new android::mock::MessageQueue();
    SFfuzz.mutableEventQueue().reset(mMessageQueue);
    SFfuzz.setupScheduler(std::make_unique<android::mock::DispSync>(),
                          std::make_unique<android::mock::EventControlThread>(),
                          std::make_unique<android::mock::EventThread>(),
                          std::make_unique<android::mock::EventThread>());
    SFfuzz.setupTimeStats(std::make_unique<android::mock::TimeStats>());
    android::renderengine::mock::RenderEngine* mRenderEngine =
            new android::renderengine::mock::RenderEngine();
    SFfuzz.setupRenderEngine(std::unique_ptr<android::renderengine::RenderEngine>(mRenderEngine));
    SFfuzz.setupComposer(std::make_unique<android::Hwc2::mock::Composer>());

    // reading in the non-privelaged codes
    setupNonPrivCodes(composerCodes);
    uint32_t range = (uint32_t)composerCodes.size() - 1; // code count

    android::String16 ifName("android.ui.ISurfaceComposer");
    fuzzed_data.writeInterfaceToken(ifName); // to pass CHECK_INTERFACE
    randomizeParcels(fuzzed_data, data, size);
    fuzzed_data.setDataPosition(0); // reset data ptr

    uint32_t whichCode = fdp.ConsumeIntegralInRange<uint32_t>(0, range);
    uint32_t code = composerCodes.at(whichCode);
    SFfuzz.onTransact(code, fuzzed_data, &reply, 0);

    return 0;
}