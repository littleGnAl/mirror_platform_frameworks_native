/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <array>
#include <unordered_set>
#include <gtest/gtest.h>
#include <dlfcn.h>
#include <android-base/unique_fd.h>
#include <hardware/hardware.h>
#include <sync/sync.h>

#define HWC2_INCLUDE_STRINGIFICATION
#define HWC2_USE_CPP11
#include <hardware/hwcomposer2.h>
#undef HWC2_INCLUDE_STRINGIFICATION
#undef HWC2_USE_CPP11

#include "Hwc2TestLayer.h"
#include "Hwc2TestLayers.h"
#include "Hwc2TestClientTarget.h"
#include "Hwc2TestVirtualDisplay.h"

void hwc2TestHotplugCallback(hwc2_callback_data_t callbackData,
        hwc2_display_t display, int32_t connected);
void hwc2_test_vsyncCallback(hwc2_callback_data_t callbackData,
        hwc2_display_t display, int64_t timestamp);

class Hwc2Test : public testing::Test {
public:

    virtual void SetUp()
    {
        hw_module_t const* hwc2Module;

        int err = hw_get_module(HWC_HARDWARE_MODULE_ID, &hwc2Module);
        ASSERT_GE(err, 0) << "failed to get hwc hardware module: "
                << strerror(-err);

        /* The following method will fail if you have not run
         * "adb shell stop" */
        err = hwc2_open(hwc2Module, &mHwc2Device);
        ASSERT_GE(err, 0) << "failed to open hwc hardware module: "
                << strerror(-err);

        populateDisplays();
    }

    virtual void TearDown()
    {

        for (auto itr = mLayers.begin(); itr != mLayers.end();) {
            hwc2_display_t display = itr->first;
            hwc2_layer_t layer = itr->second;
            itr++;
            destroyLayer(display, layer);
        }

        for (auto itr = mActiveDisplays.begin(); itr != mActiveDisplays.end();) {
            hwc2_display_t display = *itr;
            itr++;
            setPowerMode(display, HWC2_POWER_MODE_OFF);
        }

        if (mHwc2Device)
            hwc2_close(mHwc2Device);
    }

    void registerCallback(hwc2_callback_descriptor_t descriptor,
            hwc2_callback_data_t callbackData, hwc2_function_pointer_t pointer,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_REGISTER_CALLBACK>(
                getFunction(HWC2_FUNCTION_REGISTER_CALLBACK));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, descriptor,
                callbackData, pointer));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to register callback";
        }
    }

    void getDisplayType(hwc2_display_t display, hwc2_display_type_t* outType,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_GET_DISPLAY_TYPE>(
                getFunction(HWC2_FUNCTION_GET_DISPLAY_TYPE));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                    reinterpret_cast<int32_t*>(outType)));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to get display type";
        }
    }

    void hotplugCallback(hwc2_display_t display, int32_t connected)
    {
        std::lock_guard<std::mutex> lock(mHotplugMutex);

        if (!mReceivingHotplugs)
            return;

        if (connected == HWC2_CONNECTION_CONNECTED)
            mDisplays.insert(display);

        mHotplugCv.notify_all();
    }

    void createLayer(hwc2_display_t display, hwc2_layer_t* outLayer,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_CREATE_LAYER>(
                getFunction(HWC2_FUNCTION_CREATE_LAYER));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                outLayer));

        if (err == HWC2_ERROR_NONE)
            mLayers.insert(std::make_pair(display, *outLayer));

        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to create layer";
        }
    }

    void destroyLayer(hwc2_display_t display, hwc2_layer_t layer,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_DESTROY_LAYER>(
                getFunction(HWC2_FUNCTION_DESTROY_LAYER));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, layer));

        if (err == HWC2_ERROR_NONE)
            mLayers.erase(std::make_pair(display, layer));

        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to destroy layer "
                    << layer;
        }
    }

    void getDisplayAttribute(hwc2_display_t display, hwc2_config_t config,
            hwc2_attribute_t attribute, int32_t* outValue,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_GET_DISPLAY_ATTRIBUTE>(
                getFunction(HWC2_FUNCTION_GET_DISPLAY_ATTRIBUTE));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, config,
                attribute, outValue));

        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to get display attribute "
                    << getAttributeName(attribute) << " for config " << config;
        }
    }

    void getDisplayConfigs(hwc2_display_t display,
            std::vector<hwc2_config_t>* outConfigs,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_GET_DISPLAY_CONFIGS>(
                getFunction(HWC2_FUNCTION_GET_DISPLAY_CONFIGS));
        ASSERT_TRUE(pfn) << "failed to get function";

        uint32_t numConfigs = 0;

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                &numConfigs, nullptr));

        if (err == HWC2_ERROR_NONE) {
            outConfigs->resize(numConfigs);

            err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                    &numConfigs, outConfigs->data()));
        }

        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to get configs for"
                    " display " << display;
        }
    }

    void getActiveConfig(hwc2_display_t display, hwc2_config_t* outConfig,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_GET_ACTIVE_CONFIG>(
                getFunction(HWC2_FUNCTION_GET_ACTIVE_CONFIG));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                outConfig));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to get active config on"
                    " display " << display;
        }
    }

    void setActiveConfig(hwc2_display_t display, hwc2_config_t config,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_SET_ACTIVE_CONFIG>(
                getFunction(HWC2_FUNCTION_SET_ACTIVE_CONFIG));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, config));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to set active config "
                    << config;
        }
    }

    void getDozeSupport(hwc2_display_t display, int32_t* outSupport,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_GET_DOZE_SUPPORT>(
                getFunction(HWC2_FUNCTION_GET_DOZE_SUPPORT));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                outSupport));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to get doze support on"
                    " display " << display;
        }
    }

    void setPowerMode(hwc2_display_t display, hwc2_power_mode_t mode,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_SET_POWER_MODE>(
                getFunction(HWC2_FUNCTION_SET_POWER_MODE));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                mode));
        if (outErr) {
            *outErr = err;
            if (err != HWC2_ERROR_NONE)
                return;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to set power mode "
                    << getPowerModeName(mode) << " on display " << display;
        }

        if (mode == HWC2_POWER_MODE_OFF) {
            mActiveDisplays.erase(display);
        } else {
            mActiveDisplays.insert(display);
        }
    }

    void setVsyncEnabled(hwc2_display_t display, hwc2_vsync_t enabled,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_SET_VSYNC_ENABLED>(
                getFunction(HWC2_FUNCTION_SET_VSYNC_ENABLED));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                enabled));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to set vsync enabled "
                    << getVsyncName(enabled);
        }
    }

    void vsyncCallback(hwc2_display_t display, int64_t timestamp)
    {
        std::lock_guard<std::mutex> lock(mVsyncMutex);
        mVsyncDisplay = display;
        mVsyncTimestamp = timestamp;
        mVsyncCv.notify_all();
    }

    void getDisplayName(hwc2_display_t display, std::string* outName,
                hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_GET_DISPLAY_NAME>(
                getFunction(HWC2_FUNCTION_GET_DISPLAY_NAME));
        ASSERT_TRUE(pfn) << "failed to get function";

        uint32_t size = 0;

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, &size,
                nullptr));

        if (err == HWC2_ERROR_NONE) {
            std::vector<char> name(size);

            err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, &size,
                    name.data()));

            outName->assign(name.data());
        }

        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to get display name for "
                    << display;
        }
    }

    void setLayerCompositionType(hwc2_display_t display, hwc2_layer_t layer,
            hwc2_composition_t composition, hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_SET_LAYER_COMPOSITION_TYPE>(
                getFunction(HWC2_FUNCTION_SET_LAYER_COMPOSITION_TYPE));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, layer,
                composition));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to set layer composition"
                    " type " << getCompositionName(composition);
        }
    }

    void setCursorPosition(hwc2_display_t display, hwc2_layer_t layer,
            int32_t x, int32_t y, hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_SET_CURSOR_POSITION>(
                getFunction(HWC2_FUNCTION_SET_CURSOR_POSITION));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, layer, x,
                y));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to set cursor position";
        }
    }

    void setLayerBlendMode(hwc2_display_t display, hwc2_layer_t layer,
            hwc2_blend_mode_t mode, hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_SET_LAYER_BLEND_MODE>(
                getFunction(HWC2_FUNCTION_SET_LAYER_BLEND_MODE));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, layer,
                mode));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to set layer blend mode "
                    << getBlendModeName(mode);
        }
    }

    void setLayerBuffer(hwc2_display_t display, hwc2_layer_t layer,
            buffer_handle_t buffer, int32_t acquireFence,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_SET_LAYER_BUFFER>(
                getFunction(HWC2_FUNCTION_SET_LAYER_BUFFER));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, layer,
                buffer, acquireFence));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to set layer buffer";
        }
    }

    void setLayerColor(hwc2_display_t display, hwc2_layer_t layer,
            hwc_color_t color, hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_SET_LAYER_COLOR>(
                getFunction(HWC2_FUNCTION_SET_LAYER_COLOR));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, layer,
                color));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to set layer color";
        }
    }

    void setLayerDataspace(hwc2_display_t display, hwc2_layer_t layer,
            android_dataspace_t dataspace, hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_SET_LAYER_DATASPACE>(
                getFunction(HWC2_FUNCTION_SET_LAYER_DATASPACE));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                layer, dataspace));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to set layer dataspace";
        }
    }

    void setLayerDisplayFrame(hwc2_display_t display, hwc2_layer_t layer,
            const hwc_rect_t& displayFrame, hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_SET_LAYER_DISPLAY_FRAME>(
                getFunction(HWC2_FUNCTION_SET_LAYER_DISPLAY_FRAME));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, layer,
                displayFrame));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to set layer display"
                    " frame";
        }
    }

    void setLayerPlaneAlpha(hwc2_display_t display, hwc2_layer_t layer,
            float alpha, hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_SET_LAYER_PLANE_ALPHA>(
                getFunction(HWC2_FUNCTION_SET_LAYER_PLANE_ALPHA));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, layer,
                alpha));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to set layer plane alpha "
                    << alpha;
        }
    }

    void setLayerSourceCrop(hwc2_display_t display, hwc2_layer_t layer,
            const hwc_frect_t& sourceCrop, hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_SET_LAYER_SOURCE_CROP>(
                getFunction(HWC2_FUNCTION_SET_LAYER_SOURCE_CROP));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, layer,
                sourceCrop));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to set layer source crop";
        }
    }

    void setLayerSurfaceDamage(hwc2_display_t display, hwc2_layer_t layer,
            const hwc_region_t& surfaceDamage, hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_SET_LAYER_SURFACE_DAMAGE>(
                getFunction(HWC2_FUNCTION_SET_LAYER_SURFACE_DAMAGE));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, layer,
                surfaceDamage));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to set layer surface"
                    " damage";
        }
    }

    void setLayerTransform(hwc2_display_t display, hwc2_layer_t layer,
            hwc_transform_t transform, hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_SET_LAYER_TRANSFORM>(
                getFunction(HWC2_FUNCTION_SET_LAYER_TRANSFORM));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, layer,
                transform));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to set layer transform "
                    << getTransformName(transform);
        }
    }

    void setLayerVisibleRegion(hwc2_display_t display, hwc2_layer_t layer,
            const hwc_region_t& visibleRegion, hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_SET_LAYER_VISIBLE_REGION>(
                getFunction(HWC2_FUNCTION_SET_LAYER_VISIBLE_REGION));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, layer,
                visibleRegion));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to set layer visible"
                    " region";
        }
    }

    void setLayerZOrder(hwc2_display_t display, hwc2_layer_t layer,
            uint32_t zOrder, hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_SET_LAYER_Z_ORDER>(
                getFunction(HWC2_FUNCTION_SET_LAYER_Z_ORDER));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, layer,
                zOrder));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to set layer z order "
                    << zOrder;
        }
    }

    void validateDisplay(hwc2_display_t display, uint32_t* outNumTypes,
            uint32_t* outNumRequests, hwc2_error_t* outErr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_VALIDATE_DISPLAY>(
                getFunction(HWC2_FUNCTION_VALIDATE_DISPLAY));
        ASSERT_TRUE(pfn) << "failed to get function";

        *outErr = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                outNumTypes, outNumRequests));
    }

    void validateDisplay(hwc2_display_t display, uint32_t* outNumTypes,
            uint32_t* outNumRequests, bool* outHasChanges)
    {
        hwc2_error_t err = HWC2_ERROR_NONE;

        EXPECT_NO_FATAL_FAILURE(validateDisplay(display, outNumTypes,
                outNumRequests, &err));

        if (err != HWC2_ERROR_HAS_CHANGES) {
            *outHasChanges = false;
            EXPECT_EQ(err, HWC2_ERROR_NONE) << "failed to validate display";
        } else {
            *outHasChanges = true;
        }
    }

    void getDisplayRequests(hwc2_display_t display,
            hwc2_display_request_t* outDisplayRequests,
            std::vector<hwc2_layer_t>* outLayers,
            std::vector<hwc2_layer_request_t>* outLayerRequests,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_GET_DISPLAY_REQUESTS>(
                getFunction(HWC2_FUNCTION_GET_DISPLAY_REQUESTS));
        ASSERT_TRUE(pfn) << "failed to get function";

        uint32_t numElements = 0;

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                reinterpret_cast<int32_t*>(outDisplayRequests), &numElements,
                nullptr, nullptr));

        if (err == HWC2_ERROR_NONE && numElements > 0) {
            outLayers->resize(numElements);
            outLayerRequests->resize(numElements);

            err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                    reinterpret_cast<int32_t*>(outDisplayRequests), &numElements,
                    reinterpret_cast<uint64_t*>(outLayers->data()),
                    reinterpret_cast<int32_t*>(outLayerRequests->data())));
        }

        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to get display requests";
        }
    }

    void manageRequests(hwc2_display_t display,
            const std::vector<hwc2_layer_t>& layers, uint32_t numRequests,
            std::set<hwc2_layer_t>* outClearLayers = nullptr,
            bool* outFlipClientTarget = nullptr)
    {
        hwc2_display_request_t displayRequest =
                static_cast<hwc2_display_request_t>(0);
        std::vector<hwc2_layer_t> requestedLayers;
        std::vector<hwc2_layer_request_t> requests;

        ASSERT_NO_FATAL_FAILURE(getDisplayRequests(display, &displayRequest,
                &requestedLayers, &requests));

        EXPECT_EQ(numRequests, requests.size()) << "validate returned "
                << numRequests << " requests and get display requests returned "
                << requests.size() << " requests";

        for (size_t i = 0; i < requests.size(); i++) {
            hwc2_layer_t requestedLayer = requestedLayers.at(i);
            hwc2_layer_request_t request = requests.at(i);

            EXPECT_EQ(std::count(layers.begin(), layers.end(), requestedLayer),
                    0) << "get display requests returned an unknown layer";
            EXPECT_NE(request, 0) << "returned empty request for layer "
                    << requestedLayer;

            if (outClearLayers && request
                    == HWC2_LAYER_REQUEST_CLEAR_CLIENT_TARGET)
                outClearLayers->insert(requestedLayer);
        }

        if (outFlipClientTarget)
            *outFlipClientTarget = displayRequest
                    & HWC2_DISPLAY_REQUEST_FLIP_CLIENT_TARGET;
    }

    void getChangedCompositionTypes(hwc2_display_t display,
            std::vector<hwc2_layer_t>* outLayers,
            std::vector<hwc2_composition_t>* outTypes,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_GET_CHANGED_COMPOSITION_TYPES>(
                getFunction(HWC2_FUNCTION_GET_CHANGED_COMPOSITION_TYPES));
        ASSERT_TRUE(pfn) << "failed to get function";

        uint32_t numElements = 0;

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                &numElements, nullptr, nullptr));

        if (err == HWC2_ERROR_NONE && numElements > 0) {
            outLayers->resize(numElements);
            outTypes->resize(numElements);

            err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                    &numElements, reinterpret_cast<uint64_t*>(outLayers->data()),
                    reinterpret_cast<int32_t*>(outTypes->data())));
        }

        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to get changed"
                    " composition types";
        }
    }

    void manageCompositionChanges(hwc2_display_t display,
            const Hwc2TestLayers& testLayers,
            const std::vector<hwc2_layer_t>& layers, uint32_t numTypes,
            std::set<hwc2_layer_t>* outClientLayers = nullptr)
    {
        std::vector<hwc2_layer_t> changedLayers;
        std::vector<hwc2_composition_t> types;

        ASSERT_NO_FATAL_FAILURE(getChangedCompositionTypes(display,
                &changedLayers, &types));

        EXPECT_EQ(numTypes, types.size()) << "validate returned "
                << numTypes << " types and get changed composition types"
                " returned " << types.size() << " types";

        for (size_t i = 0; i < types.size(); i++) {

            auto layer = std::find(layers.begin(), layers.end(),
                    changedLayers.at(i));

            EXPECT_TRUE(layer != layers.end() || !testLayers.contains(*layer))
                    << "get changed composition types returned an unknown layer";

            hwc2_composition_t requestedType = testLayers.getComposition(*layer);
            hwc2_composition_t returnedType = types.at(i);

            EXPECT_NE(returnedType, HWC2_COMPOSITION_INVALID) << "get changed"
                    " composition types returned invalid composition";

            switch (requestedType) {
            case HWC2_COMPOSITION_CLIENT:
                EXPECT_TRUE(false) << getCompositionName(returnedType)
                        << " cannot be changed";
                break;
            case HWC2_COMPOSITION_DEVICE:
            case HWC2_COMPOSITION_SOLID_COLOR:
                EXPECT_EQ(returnedType, HWC2_COMPOSITION_CLIENT)
                        << "composition of type "
                        << getCompositionName(requestedType)
                        << " can only be changed to "
                        << getCompositionName(HWC2_COMPOSITION_CLIENT);
                break;
            case HWC2_COMPOSITION_CURSOR:
            case HWC2_COMPOSITION_SIDEBAND:
                EXPECT_TRUE(returnedType == HWC2_COMPOSITION_CLIENT
                        || returnedType == HWC2_COMPOSITION_DEVICE)
                        << "composition of type "
                        << getCompositionName(requestedType)
                        << " can only be changed to "
                        << getCompositionName(HWC2_COMPOSITION_CLIENT) << " or "
                        << getCompositionName(HWC2_COMPOSITION_DEVICE);
                break;
            default:
                EXPECT_TRUE(false) << "unknown type "
                        << getCompositionName(requestedType);
                break;
            }

            if (outClientLayers)
                if (returnedType == HWC2_COMPOSITION_CLIENT)
                    outClientLayers->insert(*layer);
        }

        if (outClientLayers)
            for (auto layer : layers)
                if (testLayers.getComposition(layer) == HWC2_COMPOSITION_CLIENT)
                    outClientLayers->insert(layer);
    }

    void acceptDisplayChanges(hwc2_display_t display,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_ACCEPT_DISPLAY_CHANGES>(
                getFunction(HWC2_FUNCTION_ACCEPT_DISPLAY_CHANGES));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to accept display changes";
        }
    }

    void getClientTargetSupport(hwc2_display_t display, int32_t width,
            int32_t height, android_pixel_format_t format,
            android_dataspace_t dataspace, hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_GET_CLIENT_TARGET_SUPPORT>(
                getFunction(HWC2_FUNCTION_GET_CLIENT_TARGET_SUPPORT));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, width,
                height, format, dataspace));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to get client target"
                    " support";
        }
    }

    void setClientTarget(hwc2_display_t display, buffer_handle_t handle,
            int32_t acquireFence, android_dataspace_t dataspace,
            hwc_region_t damage, hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_SET_CLIENT_TARGET>(
                getFunction(HWC2_FUNCTION_SET_CLIENT_TARGET));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, handle,
                acquireFence, dataspace, damage));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to set client target";
        }
    }

    void presentDisplay(hwc2_display_t display, int32_t* outPresentFence,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_PRESENT_DISPLAY>(
                getFunction(HWC2_FUNCTION_PRESENT_DISPLAY));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                outPresentFence));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to present display";
        }
    }

    void getReleaseFences(hwc2_display_t display,
            std::vector<hwc2_layer_t>* outLayers,
            std::vector<int32_t>* outFences, hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_GET_RELEASE_FENCES>(
                getFunction(HWC2_FUNCTION_GET_RELEASE_FENCES));
        ASSERT_TRUE(pfn) << "failed to get function";

        uint32_t numElements = 0;

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                &numElements, nullptr, nullptr));

        if (err == HWC2_ERROR_NONE) {
            outLayers->resize(numElements);
            outFences->resize(numElements);

            err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                    &numElements, outLayers->data(), outFences->data()));
        }

        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to get release fences";
        }
    }

    void getColorModes(hwc2_display_t display,
            std::vector<android_color_mode_t>* outColorModes,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_GET_COLOR_MODES>(
                getFunction(HWC2_FUNCTION_GET_COLOR_MODES));
        ASSERT_TRUE(pfn) << "failed to get function";

        uint32_t numColorModes = 0;

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                &numColorModes, nullptr));
        if (err == HWC2_ERROR_NONE) {
            outColorModes->resize(numColorModes);

            err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                    &numColorModes,
                    reinterpret_cast<int32_t*>(outColorModes->data())));
        }

        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to get color modes for"
                    " display " << display;
        }
    }

    void setColorMode(hwc2_display_t display, android_color_mode_t colorMode,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_SET_COLOR_MODE>(
                getFunction(HWC2_FUNCTION_SET_COLOR_MODE));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                static_cast<int32_t>(colorMode)));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to set color mode "
                    << colorMode;
        }
    }

    void getHdrCapabilities(hwc2_display_t display,
            std::vector<android_hdr_t>* outTypes, float* outMaxLuminance,
            float* outMaxAverageLuminance, float* outMinLuminance,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_GET_HDR_CAPABILITIES>(
                getFunction(HWC2_FUNCTION_GET_HDR_CAPABILITIES));
        ASSERT_TRUE(pfn) << "failed to get function";

        uint32_t numTypes = 0;

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                &numTypes, nullptr, outMaxLuminance, outMaxAverageLuminance,
                outMinLuminance));

        if (err == HWC2_ERROR_NONE) {
            outTypes->resize(numTypes);

            err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, &numTypes,
                    reinterpret_cast<int32_t*>(outTypes->data()), outMaxLuminance,
                    outMaxAverageLuminance, outMinLuminance));
        }

        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to get hdr capabilities"
                    " for display " << display;
        }
    }

    void setColorTransform(hwc2_display_t display,
            const std::array<float, 16>& matrix, android_color_transform_t hint,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_SET_COLOR_TRANSFORM>(
                getFunction(HWC2_FUNCTION_SET_COLOR_TRANSFORM));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display,
                matrix.data(), hint));

        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to set color transform "
                    << hint;
        }
    }

    void createVirtualDisplay(uint32_t width, uint32_t height,
            android_pixel_format_t* outFormat, hwc2_display_t* outDisplay,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_CREATE_VIRTUAL_DISPLAY>(
                getFunction(HWC2_FUNCTION_CREATE_VIRTUAL_DISPLAY));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, width, height,
                reinterpret_cast<int32_t*>(outFormat), outDisplay));

        if (*outErr == HWC2_ERROR_NONE)
            mVirtualDisplays.insert(*outDisplay);

        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to create virtual display";
        }
    }

    void destroyVirtualDisplay(hwc2_display_t display,
            hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_DESTROY_VIRTUAL_DISPLAY>(
                getFunction(HWC2_FUNCTION_DESTROY_VIRTUAL_DISPLAY));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display));

        if (err == HWC2_ERROR_NONE)
            mVirtualDisplays.erase(display);

        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to destroy virtual display";
        }
    }

    void getMaxVirtualDisplayCount(uint32_t* outMaxCnt)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_GET_MAX_VIRTUAL_DISPLAY_COUNT>(
                getFunction(HWC2_FUNCTION_GET_MAX_VIRTUAL_DISPLAY_COUNT));
        ASSERT_TRUE(pfn) << "failed to get function";

        *outMaxCnt = pfn(mHwc2Device);
    }

    void setOutputBuffer(hwc2_display_t display, buffer_handle_t buffer,
            int32_t releaseFence, hwc2_error_t* outErr = nullptr)
    {
        auto pfn = reinterpret_cast<HWC2_PFN_SET_OUTPUT_BUFFER>(
                getFunction(HWC2_FUNCTION_SET_OUTPUT_BUFFER));
        ASSERT_TRUE(pfn) << "failed to get function";

        auto err = static_cast<hwc2_error_t>(pfn(mHwc2Device, display, buffer,
                releaseFence));
        if (outErr) {
            *outErr = err;
        } else {
            ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to set output buffer";
        }
    }

protected:
    hwc2_function_pointer_t getFunction(hwc2_function_descriptor_t descriptor)
    {
        return mHwc2Device->getFunction(mHwc2Device, descriptor);
    }

    void getCapabilities(std::vector<hwc2_capability_t>* outCapabilities)
    {
        uint32_t num = 0;

        mHwc2Device->getCapabilities(mHwc2Device, &num, nullptr);

        outCapabilities->resize(num);

        mHwc2Device->getCapabilities(mHwc2Device, &num,
                reinterpret_cast<int32_t*>(outCapabilities->data()));
    }

    void populateDisplays()
    {
        mReceivingHotplugs = true;

        ASSERT_NO_FATAL_FAILURE(registerCallback(HWC2_CALLBACK_HOTPLUG, this,
                reinterpret_cast<hwc2_function_pointer_t>(
                hwc2TestHotplugCallback)));

        std::unique_lock<std::mutex> lock(mHotplugMutex);

        while (mHotplugCv.wait_for(lock, std::chrono::seconds(1)) !=
                std::cv_status::timeout) { }

        mReceivingHotplugs = false;
    }

    void getBadDisplay(hwc2_display_t* outDisplay)
    {
        for (hwc2_display_t display = 0; display < UINT64_MAX; display++) {
            if (mDisplays.count(display) == 0) {
                *outDisplay = display;
                return;
            }
        }
        ASSERT_TRUE(false) << "Unable to find bad display. UINT64_MAX displays"
                " are registered. This should never happen.";
    }

    /* NOTE: will create min(layerCnt, max supported layers) layers */
    void createLayers(hwc2_display_t display,
            std::vector<hwc2_layer_t>* outLayers, size_t newLayerCnt)
    {
        std::vector<hwc2_layer_t> newLayers;
        hwc2_layer_t layer;
        hwc2_error_t err = HWC2_ERROR_NONE;

        for (size_t i = 0; i < newLayerCnt; i++) {

            EXPECT_NO_FATAL_FAILURE(createLayer(display, &layer, &err));
            if (err == HWC2_ERROR_NO_RESOURCES)
                break;
            if (err != HWC2_ERROR_NONE) {
                newLayers.clear();
                ASSERT_EQ(err, HWC2_ERROR_NONE) << "failed to create layer";
            }
            newLayers.push_back(layer);
        }

        outLayers->insert(outLayers->end(), newLayers.begin(), newLayers.end());
    }

    void destroyLayers(hwc2_display_t display,
            std::vector<hwc2_layer_t>* outLayers)
    {
        for (hwc2_layer_t layer : *outLayers)
            EXPECT_NO_FATAL_FAILURE(destroyLayer(display, layer));
        outLayers->clear();
    }

    void getInvalidConfig(hwc2_display_t display, hwc2_config_t* outConfig)
    {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        std::set<hwc2_config_t> configsSet(configs.begin(), configs.end());
        hwc2_config_t CONFIG_MAX = UINT32_MAX;

        ASSERT_LE(configsSet.size() - 1, CONFIG_MAX) << "every config value"
                " (2^32 values) has been taken which shouldn't happen";

        hwc2_config_t config;
        for (config = 0; config < CONFIG_MAX; config++)
            if (configsSet.find(config) == configsSet.end())
                break;

        *outConfig = config;
    }

    void enableVsync(hwc2_display_t display)
    {
        ASSERT_NO_FATAL_FAILURE(registerCallback(HWC2_CALLBACK_VSYNC, this,
                reinterpret_cast<hwc2_function_pointer_t>(
                hwc2_test_vsyncCallback)));
        ASSERT_NO_FATAL_FAILURE(setVsyncEnabled(display, HWC2_VSYNC_ENABLE));
    }

    void disableVsync(hwc2_display_t display)
    {
        ASSERT_NO_FATAL_FAILURE(setVsyncEnabled(display, HWC2_VSYNC_DISABLE));
    }

    void waitForVsync(hwc2_display_t* outDisplay = nullptr,
            int64_t* outTimestamp = nullptr)
    {
        std::unique_lock<std::mutex> lock(mVsyncMutex);
        ASSERT_EQ(mVsyncCv.wait_for(lock, std::chrono::seconds(3)),
                std::cv_status::no_timeout) << "timed out attempting to get"
                " vsync callback";
        if (outDisplay)
            *outDisplay = mVsyncDisplay;
        if (outTimestamp)
            *outTimestamp = mVsyncTimestamp;
    }

    /* Calls a set property function from Hwc2Test to set a property value from
     * Hwc2TestLayer to hwc2_layer_t on hwc2_display_t */
    typedef void TestLayerPropertyFunction(Hwc2Test* test,
            hwc2_display_t display, hwc2_layer_t layer,
            Hwc2TestLayer* testLayer);

    /* Calls a set property function from Hwc2Test to set a bad property value
     * on hwc2_layer_t on hwc2_display_t */
    typedef void TestBadLayerPropertyFunction(Hwc2Test* test,
            hwc2_display_t display, hwc2_layer_t layer);

    /* Advances a property of Hwc2TestLayer */
    typedef bool AdvanceProperty(Hwc2TestLayer* testLayer);

    /* Is called after a display is powered on and all layer properties have
     * been set. It should be used to test functions such as validate, accepting
     * changes, present, etc. */
    typedef void TestDisplayLayersFunction(Hwc2Test* test,
            hwc2_display_t display, const std::vector<hwc2_layer_t>& layers,
            const Hwc2TestLayers& testLayers);

    /* It is called on an non validated display */
    typedef void TestDisplayNonValidatedLayersFunction(Hwc2Test* test,
            hwc2_display_t display, std::vector<hwc2_layer_t>* layers);

    /* For each active display it cycles through each display config and tests
     * each property value. It creates a layer, sets the property and then
     * destroys the layer */
    void setLayerProperty(hwc2_test_coverage_t coverage,
            TestLayerPropertyFunction function, AdvanceProperty advance)
    {
        for (auto display : mDisplays) {
            std::vector<hwc2_config_t> configs;

            ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

            for (auto config : configs) {
                hwc2_layer_t layer;
                int32_t width, height;

                ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));
                ASSERT_NO_FATAL_FAILURE(getActiveDimensions(display, &width,
                        &height));
                Hwc2TestLayer testLayer(coverage, width, height);

                do {
                    ASSERT_NO_FATAL_FAILURE(createLayer(display, &layer));

                    ASSERT_NO_FATAL_FAILURE(function(this, display, layer,
                            &testLayer));

                    ASSERT_NO_FATAL_FAILURE(destroyLayer(display, layer));
                } while (advance(&testLayer));
            }
        }
    }

    /* For each active display it cycles through each display config and tests
     * each property value. It creates a layer, cycles through each property
     * value and updates the layer property value and then destroys the layer */
    void setLayerPropertyUpdate(hwc2_test_coverage_t coverage,
            TestLayerPropertyFunction function, AdvanceProperty advance)
    {
        for (auto display : mDisplays) {
            std::vector<hwc2_config_t> configs;

            ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

            for (auto config : configs) {
                hwc2_layer_t layer;
                int32_t width, height;

                ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));
                ASSERT_NO_FATAL_FAILURE(getActiveDimensions(display, &width,
                        &height));
                Hwc2TestLayer testLayer(coverage, width, height);

                ASSERT_NO_FATAL_FAILURE(createLayer(display, &layer));

                do {
                    ASSERT_NO_FATAL_FAILURE(function(this, display, layer,
                            &testLayer));
                } while (advance(&testLayer));

                ASSERT_NO_FATAL_FAILURE(destroyLayer(display, layer));
            }
        }
    }

    /* For each active display it cycles through each display config.
     * 1) It attempts to set a valid property value to bad layer handle.
     * 2) It creates a layer x and attempts to set a valid property value to
     *    layer x + 1
     * 3) It destroys the layer x and attempts to set a valid property value to
     *    the destroyed layer x.
     */
    void setLayerPropertyBadLayer(hwc2_test_coverage_t coverage,
            TestLayerPropertyFunction function)
    {
        for (auto display : mDisplays) {
            std::vector<hwc2_config_t> configs;

            ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

            for (auto config : configs) {
                hwc2_layer_t layer = 0;
                int32_t width, height;

                ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));
                ASSERT_NO_FATAL_FAILURE(getActiveDimensions(display, &width,
                        &height));
                Hwc2TestLayer testLayer(coverage, width, height);

                ASSERT_NO_FATAL_FAILURE(function(this, display, layer,
                        &testLayer));

                ASSERT_NO_FATAL_FAILURE(createLayer(display, &layer));

                ASSERT_NO_FATAL_FAILURE(function(this, display, layer + 1,
                        &testLayer));

                ASSERT_NO_FATAL_FAILURE(destroyLayer(display, layer));

                ASSERT_NO_FATAL_FAILURE(function(this, display, layer,
                        &testLayer));
            }
        }
    }

    /* For each active display it cycles through each display config and tests
     * each property value. It creates a layer, sets a bad property value and
     * then destroys the layer */
    void setLayerPropertyBadParameter(TestBadLayerPropertyFunction function)
    {
        for (auto display : mDisplays) {
            std::vector<hwc2_config_t> configs;

            ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

            for (auto config : configs) {
                hwc2_layer_t layer;

                ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));

                ASSERT_NO_FATAL_FAILURE(createLayer(display, &layer));

                ASSERT_NO_FATAL_FAILURE(function(this, display, layer));

                ASSERT_NO_FATAL_FAILURE(destroyLayer(display, layer));
            }
        }
    }

    /* For each active display it powers on the display, cycles through each
     * config and creates a set of layers with a certain amount of coverage.
     * For each active display, for each config and for each set of layers,
     * it calls the TestDisplayLayersFunction */
    void displayLayers(hwc2_test_coverage_t coverage, size_t layerCnt,
            TestDisplayLayersFunction function)
    {
        for (auto display : mDisplays) {
            std::vector<hwc2_config_t> configs;

            ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_ON));

            ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

            for (auto config : configs) {
                int32_t width, height;
                std::vector<hwc2_layer_t> layers;

                ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));
                ASSERT_NO_FATAL_FAILURE(getActiveDimensions(display, &width, &height));

                ASSERT_NO_FATAL_FAILURE(createLayers(display, &layers, layerCnt));
                Hwc2TestLayers testLayers(layers, coverage, width, height);

                do {
                    bool skip;

                    ASSERT_NO_FATAL_FAILURE(setLayerProperties(display, layers,
                            &testLayers, &skip));
                    if (!skip)
                        EXPECT_NO_FATAL_FAILURE(function(this, display, layers,
                                testLayers));

                } while (testLayers.advance());

                ASSERT_NO_FATAL_FAILURE(destroyLayers(display, &layers));
            }

            ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_OFF));
        }
    }

    /* For each active display, it calls the
     * TestDisplayNonValidatedLayersFunction on a variety on non-validated
     * layer combinations */
    void displayNonValidatedLayers(size_t layerCnt,
            TestDisplayNonValidatedLayersFunction function)
    {
        for (auto display : mDisplays) {
            uint32_t numTypes, numRequests;
            std::vector<hwc2_layer_t> layers;
            bool hasChanges;

            ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_ON));

            EXPECT_NO_FATAL_FAILURE(function(this, display, &layers));

            ASSERT_NO_FATAL_FAILURE(createLayers(display, &layers, layerCnt));

            EXPECT_NO_FATAL_FAILURE(function(this, display, &layers));

            for (auto layer : layers)
                ASSERT_NO_FATAL_FAILURE(setLayerCompositionType(display, layer,
                        HWC2_COMPOSITION_CLIENT));

            EXPECT_NO_FATAL_FAILURE(function(this, display, &layers));

            ASSERT_NO_FATAL_FAILURE(validateDisplay(display, &numTypes,
                    &numRequests, &hasChanges));

            for (auto layer : layers)
                ASSERT_NO_FATAL_FAILURE(setLayerCompositionType(display, layer,
                        HWC2_COMPOSITION_DEVICE));

            EXPECT_NO_FATAL_FAILURE(function(this, display, &layers));

            ASSERT_NO_FATAL_FAILURE(destroyLayers(display, &layers));

            EXPECT_NO_FATAL_FAILURE(function(this, display, &layers));

            ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_OFF));
        }
    }

    void getActiveConfigAttribute(hwc2_display_t display,
            hwc2_attribute_t attribute, int32_t* outValue)
    {
        hwc2_config_t config;
        ASSERT_NO_FATAL_FAILURE(getActiveConfig(display, &config));
        ASSERT_NO_FATAL_FAILURE(getDisplayAttribute(display, config,
                attribute, outValue));
        ASSERT_GE(*outValue, 0) << "failed to get valid "
                << getAttributeName(attribute);
    }

    void getActiveDimensions(hwc2_display_t display, int32_t* outWidth,
            int32_t* outHeight)
    {
        ASSERT_NO_FATAL_FAILURE(getActiveConfigAttribute(display,
                HWC2_ATTRIBUTE_WIDTH, outWidth));
        ASSERT_NO_FATAL_FAILURE(getActiveConfigAttribute(display,
                HWC2_ATTRIBUTE_HEIGHT, outHeight));
    }

    void closeFences(hwc2_display_t display, int32_t presentFence)
    {
        std::vector<hwc2_layer_t> layers;
        std::vector<int32_t> fences;
        const int msWait = 3000;

        if (presentFence >= 0) {
            ASSERT_GE(sync_wait(presentFence, msWait), 0);
            close(presentFence);
        }

        ASSERT_NO_FATAL_FAILURE(getReleaseFences(display, &layers, &fences));
        EXPECT_EQ(layers.size(), fences.size());

        for (int32_t fence : fences) {
            EXPECT_GE(sync_wait(fence, msWait), 0);
            if (fence >= 0)
                close(fence);
        }
    }

    void setLayerProperties(hwc2_display_t display, hwc2_layer_t layer,
            Hwc2TestLayers* testLayers, bool* outSkip)
    {
        hwc2_composition_t composition;
        buffer_handle_t handle = nullptr;
        int32_t acquireFence;
        hwc2_error_t err = HWC2_ERROR_NONE;
        *outSkip = true;

        if (!testLayers->contains(layer))
            return;

        composition = testLayers->getComposition(layer);

        /* If the device cannot support a buffer format, then do not continue */
        if ((composition == HWC2_COMPOSITION_DEVICE
                || composition == HWC2_COMPOSITION_CURSOR)
                && testLayers->getBuffer(layer, &handle, &acquireFence) < 0)
            return;

        EXPECT_NO_FATAL_FAILURE(setLayerCompositionType(display, layer,
                composition, &err));
        if (err == HWC2_ERROR_UNSUPPORTED)
            EXPECT_TRUE(composition != HWC2_COMPOSITION_CLIENT
                    && composition != HWC2_COMPOSITION_DEVICE);

        std::pair<int32_t, int32_t> cursor = testLayers->getCursor(layer);

        EXPECT_NO_FATAL_FAILURE(setLayerBuffer(display, layer, handle,
                acquireFence));
        EXPECT_NO_FATAL_FAILURE(setLayerBlendMode(display, layer,
                testLayers->getBlendMode(layer)));
        EXPECT_NO_FATAL_FAILURE(setLayerColor(display, layer,
                testLayers->getColor(layer)));
        EXPECT_NO_FATAL_FAILURE(setCursorPosition(display, layer,
                cursor.first, cursor.second));
        EXPECT_NO_FATAL_FAILURE(setLayerDataspace(display, layer,
                testLayers->getDataspace(layer)));
        EXPECT_NO_FATAL_FAILURE(setLayerDisplayFrame(display, layer,
                testLayers->getDisplayFrame(layer)));
        EXPECT_NO_FATAL_FAILURE(setLayerPlaneAlpha(display, layer,
                testLayers->getPlaneAlpha(layer)));
        EXPECT_NO_FATAL_FAILURE(setLayerSourceCrop(display, layer,
                testLayers->getSourceCrop(layer)));
        EXPECT_NO_FATAL_FAILURE(setLayerSurfaceDamage(display, layer,
                testLayers->getSurfaceDamage(layer)));
        EXPECT_NO_FATAL_FAILURE(setLayerTransform(display, layer,
                testLayers->getTransform(layer)));
        EXPECT_NO_FATAL_FAILURE(setLayerVisibleRegion(display, layer,
                testLayers->getVisibleRegion(layer)));
        EXPECT_NO_FATAL_FAILURE(setLayerZOrder(display, layer,
                testLayers->getZOrder(layer)));

        *outSkip = false;
    }

    void setLayerProperties(hwc2_display_t display,
            const std::vector<hwc2_layer_t>& layers,
            Hwc2TestLayers* testLayers, bool* outSkip)
    {
        for (auto layer : layers) {
            EXPECT_NO_FATAL_FAILURE(setLayerProperties(display, layer,
                    testLayers, outSkip));
            if (*outSkip)
                return;
        }
    }

    void setClientTarget(hwc2_display_t display,
            Hwc2TestClientTarget* testClientTarget,
            const Hwc2TestLayers& testLayers,
            const std::set<hwc2_layer_t> clientLayers,
            const std::set<hwc2_layer_t> clearLayers, bool flipClientTarget,
            int32_t displayWidth, int32_t displayHeight)
    {
        android_dataspace_t dataspace = HAL_DATASPACE_UNKNOWN;
        hwc_region_t damage = { };
        buffer_handle_t handle;
        int32_t acquireFence;

        ASSERT_EQ(testClientTarget->getBuffer(testLayers, clientLayers,
                clearLayers, flipClientTarget, displayWidth, displayHeight,
                &handle, &acquireFence), 0);
        EXPECT_NO_FATAL_FAILURE(setClientTarget(display, handle, acquireFence,
                dataspace, damage));
    }

    void presentDisplays(size_t layerCnt, hwc2_test_coverage_t coverage,
            const std::map<hwc2_test_property_t, hwc2_test_coverage_t>&
            coverageExceptions, bool optimize)
    {
        for (auto display : mDisplays) {
            std::vector<hwc2_config_t> configs;

            ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_ON));
            ASSERT_NO_FATAL_FAILURE(enableVsync(display));

            ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

            for (auto config : configs) {
                int32_t width, height;
                std::vector<hwc2_layer_t> layers;

                ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));
                ASSERT_NO_FATAL_FAILURE(getActiveDimensions(display, &width,
                        &height));

                ASSERT_NO_FATAL_FAILURE(createLayers(display, &layers, layerCnt));
                Hwc2TestLayers testLayers(layers, coverage, width, height,
                        coverageExceptions);

                if (optimize && !testLayers.optimizeLayouts())
                    continue;

                std::set<hwc2_layer_t> clientLayers;
                std::set<hwc2_layer_t> clearLayers;
                Hwc2TestClientTarget testClientTarget;

                do {
                    uint32_t numTypes, numRequests;
                    bool hasChanges, skip;
                    bool flipClientTarget;
                    int32_t presentFence;

                    ASSERT_NO_FATAL_FAILURE(setLayerProperties(display, layers,
                            &testLayers, &skip));
                    if (skip)
                        continue;

                    ASSERT_NO_FATAL_FAILURE(validateDisplay(display, &numTypes,
                            &numRequests, &hasChanges));
                    if (hasChanges)
                        EXPECT_LE(numTypes, static_cast<uint32_t>(layers.size()))
                                << "wrong number of requests";

                    ASSERT_NO_FATAL_FAILURE(manageCompositionChanges(display,
                            testLayers, layers, numTypes, &clientLayers));
                    ASSERT_NO_FATAL_FAILURE(manageRequests(display, layers,
                            numRequests, &clearLayers, &flipClientTarget));
                    ASSERT_NO_FATAL_FAILURE(setClientTarget(display,
                            &testClientTarget, testLayers, clientLayers,
                            clearLayers, flipClientTarget, width, height));
                    ASSERT_NO_FATAL_FAILURE(acceptDisplayChanges(display));

                    ASSERT_NO_FATAL_FAILURE(waitForVsync());

                    EXPECT_NO_FATAL_FAILURE(presentDisplay(display,
                            &presentFence));

                    ASSERT_NO_FATAL_FAILURE(closeFences(display, presentFence));

                    clientLayers.clear();
                    clearLayers.clear();

                } while (testLayers.advance());

                ASSERT_NO_FATAL_FAILURE(destroyLayers(display, &layers));
            }

            ASSERT_NO_FATAL_FAILURE(disableVsync(display));
            ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_OFF));
        }
    }

    hwc2_device_t* mHwc2Device = nullptr;

    std::mutex mHotplugMutex;
    std::condition_variable mHotplugCv;
    bool mReceivingHotplugs = false;
    std::unordered_set<hwc2_display_t> mDisplays;

    /* Store all created layers that have not been destroyed. If an ASSERT_*
     * fails, then destroy the layers on exit */
    std::set<std::pair<hwc2_display_t, hwc2_layer_t>> mLayers;

    /* Store the power mode state. If it is not HWC2_POWER_MODE_OFF when
     * tearing down the test cases, change it to HWC2_POWER_MODE_OFF */
    std::set<hwc2_display_t> mActiveDisplays;

    /* Store all created virtual displays that have not been destroyed. If an
     * ASSERT_* fails, then destroy the virtual displays on exit */
    std::set<hwc2_display_t> mVirtualDisplays;

    std::mutex mVsyncMutex;
    std::condition_variable mVsyncCv;
    hwc2_display_t mVsyncDisplay;
    int64_t mVsyncTimestamp = -1;
};

void hwc2TestHotplugCallback(hwc2_callback_data_t callbackData,
        hwc2_display_t display, int32_t connection)
{
    if (callbackData)
        static_cast<Hwc2Test*>(callbackData)->hotplugCallback(display,
                connection);
}

void hwc2_test_vsyncCallback(hwc2_callback_data_t callbackData,
        hwc2_display_t display, int64_t timestamp)
{
    if (callbackData)
        static_cast<Hwc2Test*>(callbackData)->vsyncCallback(display,
                timestamp);
}


static const std::array<hwc2_function_descriptor_t, 42> requiredFunctions = {{
    HWC2_FUNCTION_ACCEPT_DISPLAY_CHANGES,
    HWC2_FUNCTION_CREATE_LAYER,
    HWC2_FUNCTION_CREATE_VIRTUAL_DISPLAY,
    HWC2_FUNCTION_DESTROY_LAYER,
    HWC2_FUNCTION_DESTROY_VIRTUAL_DISPLAY,
    HWC2_FUNCTION_DUMP,
    HWC2_FUNCTION_GET_ACTIVE_CONFIG,
    HWC2_FUNCTION_GET_CHANGED_COMPOSITION_TYPES,
    HWC2_FUNCTION_GET_CLIENT_TARGET_SUPPORT,
    HWC2_FUNCTION_GET_COLOR_MODES,
    HWC2_FUNCTION_GET_DISPLAY_ATTRIBUTE,
    HWC2_FUNCTION_GET_DISPLAY_CONFIGS,
    HWC2_FUNCTION_GET_DISPLAY_NAME,
    HWC2_FUNCTION_GET_DISPLAY_REQUESTS,
    HWC2_FUNCTION_GET_DISPLAY_TYPE,
    HWC2_FUNCTION_GET_DOZE_SUPPORT,
    HWC2_FUNCTION_GET_HDR_CAPABILITIES,
    HWC2_FUNCTION_GET_MAX_VIRTUAL_DISPLAY_COUNT,
    HWC2_FUNCTION_GET_RELEASE_FENCES,
    HWC2_FUNCTION_PRESENT_DISPLAY,
    HWC2_FUNCTION_REGISTER_CALLBACK,
    HWC2_FUNCTION_SET_ACTIVE_CONFIG,
    HWC2_FUNCTION_SET_CLIENT_TARGET,
    HWC2_FUNCTION_SET_COLOR_MODE,
    HWC2_FUNCTION_SET_COLOR_TRANSFORM,
    HWC2_FUNCTION_SET_CURSOR_POSITION,
    HWC2_FUNCTION_SET_LAYER_BLEND_MODE,
    HWC2_FUNCTION_SET_LAYER_BUFFER,
    HWC2_FUNCTION_SET_LAYER_COLOR,
    HWC2_FUNCTION_SET_LAYER_COMPOSITION_TYPE,
    HWC2_FUNCTION_SET_LAYER_DATASPACE,
    HWC2_FUNCTION_SET_LAYER_DISPLAY_FRAME,
    HWC2_FUNCTION_SET_LAYER_PLANE_ALPHA,
    HWC2_FUNCTION_SET_LAYER_SOURCE_CROP,
    HWC2_FUNCTION_SET_LAYER_SURFACE_DAMAGE,
    HWC2_FUNCTION_SET_LAYER_TRANSFORM,
    HWC2_FUNCTION_SET_LAYER_VISIBLE_REGION,
    HWC2_FUNCTION_SET_LAYER_Z_ORDER,
    HWC2_FUNCTION_SET_OUTPUT_BUFFER,
    HWC2_FUNCTION_SET_POWER_MODE,
    HWC2_FUNCTION_SET_VSYNC_ENABLED,
    HWC2_FUNCTION_VALIDATE_DISPLAY,
}};

TEST_F(Hwc2Test, GET_FUNCTION)
{
    for (hwc2_function_descriptor_t descriptor : requiredFunctions) {
        hwc2_function_pointer_t pfn = getFunction(descriptor);
        EXPECT_TRUE(pfn) << "failed to get function "
                << getFunctionDescriptorName(descriptor);
    }
}

TEST_F(Hwc2Test, GET_FUNCTION_invalid_function)
{
    hwc2_function_pointer_t pfn = getFunction(HWC2_FUNCTION_INVALID);
    EXPECT_FALSE(pfn) << "failed to get invalid function";
}

TEST_F(Hwc2Test, GET_CAPABILITIES)
{
    std::vector<hwc2_capability_t> capabilities;

    getCapabilities(&capabilities);

    EXPECT_EQ(std::count(capabilities.begin(), capabilities.end(),
            HWC2_CAPABILITY_INVALID), 0);
}

static const std::array<hwc2_callback_descriptor_t, 3> callbackDescriptors = {{
    HWC2_CALLBACK_HOTPLUG,
    HWC2_CALLBACK_REFRESH,
    HWC2_CALLBACK_VSYNC,
}};

TEST_F(Hwc2Test, REGISTER_CALLBACK)
{
    hwc2_callback_data_t data = (hwc2_callback_data_t) "data";

    for (auto descriptor : callbackDescriptors)
        ASSERT_NO_FATAL_FAILURE(registerCallback(descriptor, data,
                []() { return; }));
}

TEST_F(Hwc2Test, REGISTER_CALLBACK_bad_parameter)
{
    hwc2_callback_data_t data = (hwc2_callback_data_t) "data";
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(registerCallback(HWC2_CALLBACK_INVALID, data,
            []() { return; }, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_PARAMETER) << "returned wrong error code";
}

TEST_F(Hwc2Test, REGISTER_CALLBACK_null_data)
{
    hwc2_callback_data_t data = nullptr;

    for (auto descriptor : callbackDescriptors)
        ASSERT_NO_FATAL_FAILURE(registerCallback(descriptor, data,
                []() { return; }));
}

TEST_F(Hwc2Test, GET_DISPLAY_TYPE)
{
    for (auto display : mDisplays) {
        hwc2_display_type_t type;

        ASSERT_NO_FATAL_FAILURE(getDisplayType(display, &type));
        EXPECT_EQ(type, HWC2_DISPLAY_TYPE_PHYSICAL) << "failed to return"
                " correct display type";
    }
}

TEST_F(Hwc2Test, GET_DISPLAY_TYPE_bad_display)
{
    hwc2_display_t display;
    hwc2_display_type_t type;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    ASSERT_NO_FATAL_FAILURE(getDisplayType(display, &type, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

TEST_F(Hwc2Test, CREATE_DESTROY_LAYER)
{
    for (auto display : mDisplays) {
        hwc2_layer_t layer;

        ASSERT_NO_FATAL_FAILURE(createLayer(display, &layer));

        ASSERT_NO_FATAL_FAILURE(destroyLayer(display, layer));
    }
}

TEST_F(Hwc2Test, CREATE_LAYER_bad_display)
{
    hwc2_display_t display;
    hwc2_layer_t layer;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    ASSERT_NO_FATAL_FAILURE(createLayer(display, &layer, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

TEST_F(Hwc2Test, CREATE_LAYER_no_resources)
{
    const size_t layerCnt = 1000;

    for (auto display : mDisplays) {
        std::vector<hwc2_layer_t> layers;

        ASSERT_NO_FATAL_FAILURE(createLayers(display, &layers, layerCnt));

        ASSERT_NO_FATAL_FAILURE(destroyLayers(display, &layers));
    }
}

TEST_F(Hwc2Test, DESTROY_LAYER_bad_display)
{
    hwc2_display_t badDisplay;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&badDisplay));

    for (auto display : mDisplays) {
        hwc2_layer_t layer = 0;
        hwc2_error_t err = HWC2_ERROR_NONE;

        ASSERT_NO_FATAL_FAILURE(destroyLayer(badDisplay, layer, &err));
        EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";

        ASSERT_NO_FATAL_FAILURE(createLayer(display, &layer));

        ASSERT_NO_FATAL_FAILURE(destroyLayer(badDisplay, layer, &err));
        EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";

        ASSERT_NO_FATAL_FAILURE(destroyLayer(display, layer));
    }
}

TEST_F(Hwc2Test, DESTROY_LAYER_bad_layer)
{
    for (auto display : mDisplays) {
        hwc2_layer_t layer;
        hwc2_error_t err = HWC2_ERROR_NONE;

        ASSERT_NO_FATAL_FAILURE(destroyLayer(display, UINT64_MAX / 2, &err));
        EXPECT_EQ(err, HWC2_ERROR_BAD_LAYER) << "returned wrong error code";

        ASSERT_NO_FATAL_FAILURE(destroyLayer(display, 0, &err));
        EXPECT_EQ(err, HWC2_ERROR_BAD_LAYER) << "returned wrong error code";

        ASSERT_NO_FATAL_FAILURE(destroyLayer(display, UINT64_MAX - 1, &err));
        EXPECT_EQ(err, HWC2_ERROR_BAD_LAYER) << "returned wrong error code";

        ASSERT_NO_FATAL_FAILURE(destroyLayer(display, 1, &err));
        EXPECT_EQ(err, HWC2_ERROR_BAD_LAYER) << "returned wrong error code";

        ASSERT_NO_FATAL_FAILURE(destroyLayer(display, UINT64_MAX, &err));
        EXPECT_EQ(err, HWC2_ERROR_BAD_LAYER) << "returned wrong error code";

        ASSERT_NO_FATAL_FAILURE(createLayer(display, &layer));

        ASSERT_NO_FATAL_FAILURE(destroyLayer(display, layer + 1, &err));
        EXPECT_EQ(err, HWC2_ERROR_BAD_LAYER) << "returned wrong error code";

        ASSERT_NO_FATAL_FAILURE(destroyLayer(display, layer));

        ASSERT_NO_FATAL_FAILURE(destroyLayer(display, layer, &err));
        EXPECT_EQ(err, HWC2_ERROR_BAD_LAYER) << "returned wrong error code";
    }
}

static const std::array<hwc2_attribute_t, 2> requiredAttributes = {{
    HWC2_ATTRIBUTE_WIDTH,
    HWC2_ATTRIBUTE_HEIGHT,
}};

static const std::array<hwc2_attribute_t, 3> optionalAttributes = {{
    HWC2_ATTRIBUTE_VSYNC_PERIOD,
    HWC2_ATTRIBUTE_DPI_X,
    HWC2_ATTRIBUTE_DPI_Y,
}};

TEST_F(Hwc2Test, GET_DISPLAY_ATTRIBUTE)
{
    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs) {
            int32_t value;

            for (auto attribute : requiredAttributes) {
                ASSERT_NO_FATAL_FAILURE(getDisplayAttribute(display, config,
                        attribute, &value));
                EXPECT_GE(value, 0) << "missing required attribute "
                        << getAttributeName(attribute) << " for config "
                        << config;
            }
            for (auto attribute : optionalAttributes)
                ASSERT_NO_FATAL_FAILURE(getDisplayAttribute(display, config,
                        attribute, &value));
        }
    }
}

TEST_F(Hwc2Test, GET_DISPLAY_ATTRIBUTE_invalid_attribute)
{
    hwc2_attribute_t attribute = HWC2_ATTRIBUTE_INVALID;

    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs) {
            int32_t value;
            hwc2_error_t err = HWC2_ERROR_NONE;

            ASSERT_NO_FATAL_FAILURE(getDisplayAttribute(display, config,
                    attribute, &value, &err));
            EXPECT_EQ(value, -1) << "failed to return -1 for an invalid"
                    " attribute for config " << config;
        }
    }
}

TEST_F(Hwc2Test, GET_DISPLAY_ATTRIBUTE_bad_display)
{
    hwc2_display_t display;
    const hwc2_config_t config = 0;
    int32_t value;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    for (auto attribute : requiredAttributes) {
        ASSERT_NO_FATAL_FAILURE(getDisplayAttribute(display, config, attribute,
                &value, &err));
        EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
    }

    for (auto attribute : optionalAttributes) {
        ASSERT_NO_FATAL_FAILURE(getDisplayAttribute(display, config, attribute,
                &value, &err));
        EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
    }
}

TEST_F(Hwc2Test, GET_DISPLAY_ATTRIBUTE_bad_config)
{
    for (auto display : mDisplays) {
        hwc2_config_t config;
        int32_t value;
        hwc2_error_t err = HWC2_ERROR_NONE;

        ASSERT_NO_FATAL_FAILURE(getInvalidConfig(display, &config));

        for (auto attribute : requiredAttributes) {
            ASSERT_NO_FATAL_FAILURE(getDisplayAttribute(display, config,
                    attribute, &value, &err));
            EXPECT_EQ(err, HWC2_ERROR_BAD_CONFIG) << "returned wrong error code";
        }

        for (auto attribute : optionalAttributes) {
            ASSERT_NO_FATAL_FAILURE(getDisplayAttribute(display, config,
                    attribute, &value, &err));
            EXPECT_EQ(err, HWC2_ERROR_BAD_CONFIG) << "returned wrong error code";
        }
    }
}

TEST_F(Hwc2Test, GET_DISPLAY_CONFIGS)
{
    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));
    }
}

TEST_F(Hwc2Test, GET_DISPLAY_CONFIGS_bad_display)
{
    hwc2_display_t display;
    std::vector<hwc2_config_t> configs;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs, &err));

    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
    EXPECT_TRUE(configs.empty()) << "returned configs for bad display";
}

TEST_F(Hwc2Test, GET_DISPLAY_CONFIGS_same)
{
    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs1, configs2;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs1));
        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs2));

        EXPECT_TRUE(std::is_permutation(configs1.begin(), configs1.end(),
                configs2.begin())) << "returned two different config sets";
    }
}

TEST_F(Hwc2Test, GET_DISPLAY_CONFIGS_duplicate)
{
    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        std::set<hwc2_config_t> configsSet(configs.begin(), configs.end());
        EXPECT_EQ(configs.size(), configsSet.size()) << "returned duplicate"
                " configs";
    }
}

TEST_F(Hwc2Test, GET_ACTIVE_CONFIG)
{
    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs) {
            hwc2_config_t activeConfig;

            ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));
            ASSERT_NO_FATAL_FAILURE(getActiveConfig(display, &activeConfig));

            EXPECT_EQ(activeConfig, config) << "failed to get active config";
        }
    }
}

TEST_F(Hwc2Test, GET_ACTIVE_CONFIG_bad_display)
{
    hwc2_display_t display;
    hwc2_config_t activeConfig;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    ASSERT_NO_FATAL_FAILURE(getActiveConfig(display, &activeConfig, &err));

    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

TEST_F(Hwc2Test, GET_ACTIVE_CONFIG_bad_config)
{
    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;
        hwc2_config_t activeConfig;
        hwc2_error_t err = HWC2_ERROR_NONE;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        if (configs.empty())
            return;

        ASSERT_NO_FATAL_FAILURE(getActiveConfig(display, &activeConfig, &err));
        if (err == HWC2_ERROR_NONE) {
            EXPECT_NE(std::count(configs.begin(), configs.end(),
                    activeConfig), 0) << "active config is not found in "
                    " configs for display";
        } else {
            EXPECT_EQ(err, HWC2_ERROR_BAD_CONFIG) << "returned wrong error code";
        }
    }
}

TEST_F(Hwc2Test, SET_ACTIVE_CONFIG)
{
    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs)
            EXPECT_NO_FATAL_FAILURE(setActiveConfig(display, config));
    }
}

TEST_F(Hwc2Test, SET_ACTIVE_CONFIG_bad_display)
{
    hwc2_display_t display;
    const hwc2_config_t config = 0;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

TEST_F(Hwc2Test, SET_ACTIVE_CONFIG_bad_config)
{
    for (auto display : mDisplays) {
        hwc2_config_t config;
        hwc2_error_t err = HWC2_ERROR_NONE;

        ASSERT_NO_FATAL_FAILURE(getInvalidConfig(display, &config));

        ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config, &err));
        EXPECT_EQ(err, HWC2_ERROR_BAD_CONFIG) << "returned wrong error code";
    }
}

TEST_F(Hwc2Test, GET_DOZE_SUPPORT)
{
    for (auto display : mDisplays) {
        int32_t support = -1;

        ASSERT_NO_FATAL_FAILURE(getDozeSupport(display, &support));

        EXPECT_TRUE(support == 0 || support == 1) << "invalid doze support value";
    }
}

TEST_F(Hwc2Test, GET_DOZE_SUPPORT_bad_display)
{
    hwc2_display_t display;
    int32_t support = -1;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    ASSERT_NO_FATAL_FAILURE(getDozeSupport(display, &support, &err));

    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

TEST_F(Hwc2Test, SET_POWER_MODE)
{
    for (auto display : mDisplays) {
        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_ON));
        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_OFF));

        int32_t support = -1;
        ASSERT_NO_FATAL_FAILURE(getDozeSupport(display, &support));
        if (!support)
            return;

        ASSERT_EQ(support, 1) << "invalid doze support value";

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_DOZE));
        ASSERT_NO_FATAL_FAILURE(setPowerMode(display,
                HWC2_POWER_MODE_DOZE_SUSPEND));

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_OFF));
    }
}

TEST_F(Hwc2Test, SET_POWER_MODE_bad_display)
{
    hwc2_display_t display;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_ON, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";

    ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_OFF, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";

    int32_t support = -1;
    ASSERT_NO_FATAL_FAILURE(getDozeSupport(display, &support, &err));
    if (!support)
        return;

    ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_DOZE, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";

    ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_DOZE_SUSPEND,
            &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

TEST_F(Hwc2Test, SET_POWER_MODE_bad_parameter)
{
    for (auto display : mDisplays) {
        hwc2_power_mode_t mode = static_cast<hwc2_power_mode_t>(
                HWC2_POWER_MODE_DOZE_SUSPEND + 1);
        hwc2_error_t err = HWC2_ERROR_NONE;

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, mode, &err));
        EXPECT_EQ(err, HWC2_ERROR_BAD_PARAMETER) << "returned wrong error code "
                << mode;
    }
}

TEST_F(Hwc2Test, SET_POWER_MODE_unsupported)
{
    for (auto display : mDisplays) {
        int32_t support = -1;
        hwc2_error_t err = HWC2_ERROR_NONE;

        ASSERT_NO_FATAL_FAILURE(getDozeSupport(display, &support, &err));
        if (support == 1)
            return;

        ASSERT_EQ(support, 0) << "invalid doze support value";

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_DOZE,
                &err));
        EXPECT_EQ(err, HWC2_ERROR_UNSUPPORTED) << "returned wrong error code";

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display,
                HWC2_POWER_MODE_DOZE_SUSPEND, &err));
        EXPECT_EQ(err, HWC2_ERROR_UNSUPPORTED) <<  "returned wrong error code";
    }
}

TEST_F(Hwc2Test, SET_POWER_MODE_stress)
{
    for (auto display : mDisplays) {
        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_OFF));
        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_OFF));

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_ON));
        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_ON));

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_OFF));
        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_OFF));

        int32_t support = -1;
        ASSERT_NO_FATAL_FAILURE(getDozeSupport(display, &support));
        if (!support)
            return;

        ASSERT_EQ(support, 1) << "invalid doze support value";

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_DOZE));
        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_DOZE));

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display,
                HWC2_POWER_MODE_DOZE_SUSPEND));
        ASSERT_NO_FATAL_FAILURE(setPowerMode(display,
                HWC2_POWER_MODE_DOZE_SUSPEND));

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_OFF));
    }
}

TEST_F(Hwc2Test, SET_VSYNC_ENABLED)
{
    for (auto display : mDisplays) {
        hwc2_callback_data_t data = (hwc2_callback_data_t) "data";

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_ON));

        ASSERT_NO_FATAL_FAILURE(registerCallback(HWC2_CALLBACK_VSYNC, data,
                []() { return; }));

        ASSERT_NO_FATAL_FAILURE(setVsyncEnabled(display, HWC2_VSYNC_ENABLE));

        ASSERT_NO_FATAL_FAILURE(setVsyncEnabled(display, HWC2_VSYNC_DISABLE));

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_OFF));
    }
}

TEST_F(Hwc2Test, SET_VSYNC_ENABLED_callback)
{
    for (auto display : mDisplays) {
        hwc2_display_t receivedDisplay;
        int64_t receivedTimestamp;

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_ON));

        ASSERT_NO_FATAL_FAILURE(enableVsync(display));

        ASSERT_NO_FATAL_FAILURE(waitForVsync(&receivedDisplay,
                &receivedTimestamp));

        EXPECT_EQ(receivedDisplay, display) << "failed to get correct display";
        EXPECT_GE(receivedTimestamp, 0) << "failed to get valid timestamp";

        ASSERT_NO_FATAL_FAILURE(disableVsync(display));

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_OFF));
    }
}

TEST_F(Hwc2Test, SET_VSYNC_ENABLED_bad_display)
{
    hwc2_display_t display;
    hwc2_callback_data_t data = (hwc2_callback_data_t) "data";
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    ASSERT_NO_FATAL_FAILURE(registerCallback(HWC2_CALLBACK_VSYNC, data,
            []() { return; }));

    ASSERT_NO_FATAL_FAILURE(setVsyncEnabled(display, HWC2_VSYNC_ENABLE, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";

    ASSERT_NO_FATAL_FAILURE(setVsyncEnabled(display, HWC2_VSYNC_DISABLE, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

TEST_F(Hwc2Test, SET_VSYNC_ENABLED_bad_parameter)
{
    for (auto display : mDisplays) {
        hwc2_callback_data_t data = (hwc2_callback_data_t) "data";
        hwc2_error_t err = HWC2_ERROR_NONE;

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_ON));

        ASSERT_NO_FATAL_FAILURE(registerCallback(HWC2_CALLBACK_VSYNC, data,
                []() { return; }));

        ASSERT_NO_FATAL_FAILURE(setVsyncEnabled(display, HWC2_VSYNC_INVALID,
                &err));
        EXPECT_EQ(err, HWC2_ERROR_BAD_PARAMETER) << "returned wrong error code";

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_OFF));
    }
}

TEST_F(Hwc2Test, SET_VSYNC_ENABLED_stress)
{
    for (auto display : mDisplays) {
        hwc2_callback_data_t data = (hwc2_callback_data_t) "data";

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_ON));

        ASSERT_NO_FATAL_FAILURE(registerCallback(HWC2_CALLBACK_VSYNC, data,
                []() { return; }));

        ASSERT_NO_FATAL_FAILURE(setVsyncEnabled(display, HWC2_VSYNC_DISABLE));

        ASSERT_NO_FATAL_FAILURE(setVsyncEnabled(display, HWC2_VSYNC_ENABLE));
        ASSERT_NO_FATAL_FAILURE(setVsyncEnabled(display, HWC2_VSYNC_ENABLE));

        ASSERT_NO_FATAL_FAILURE(setVsyncEnabled(display, HWC2_VSYNC_DISABLE));
        ASSERT_NO_FATAL_FAILURE(setVsyncEnabled(display, HWC2_VSYNC_DISABLE));

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_OFF));
    }
}

TEST_F(Hwc2Test, SET_VSYNC_ENABLED_no_callback_no_power)
{
    const uint secs = 1;

    for (auto display : mDisplays) {
        ASSERT_NO_FATAL_FAILURE(setVsyncEnabled(display, HWC2_VSYNC_ENABLE));

        sleep(secs);

        ASSERT_NO_FATAL_FAILURE(setVsyncEnabled(display, HWC2_VSYNC_DISABLE));
    }
}

TEST_F(Hwc2Test, SET_VSYNC_ENABLED_no_callback)
{
    const uint secs = 1;

    for (auto display : mDisplays) {
        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_ON));

        ASSERT_NO_FATAL_FAILURE(setVsyncEnabled(display, HWC2_VSYNC_ENABLE));

        sleep(secs);

        ASSERT_NO_FATAL_FAILURE(setVsyncEnabled(display, HWC2_VSYNC_DISABLE));

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_OFF));
    }
}

TEST_F(Hwc2Test, GET_DISPLAY_NAME)
{
    for (auto display : mDisplays) {
        std::string name;

        ASSERT_NO_FATAL_FAILURE(getDisplayName(display, &name));
    }
}

TEST_F(Hwc2Test, GET_DISPLAY_NAME_bad_display)
{
    hwc2_display_t display;
    std::string name;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    ASSERT_NO_FATAL_FAILURE(getDisplayName(display, &name, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

TEST_F(Hwc2Test, SET_LAYER_COMPOSITION_TYPE)
{
    ASSERT_NO_FATAL_FAILURE(setLayerProperty(HWC2_TEST_COVERAGE_BASIC,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                EXPECT_NO_FATAL_FAILURE(test->setLayerCompositionType(display,
                        layer, testLayer->getComposition()));
            },

            [] (Hwc2TestLayer* testLayer) {
                    return testLayer->advanceComposition();
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_COMPOSITION_TYPE_bad_layer)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyBadLayer(HWC2_TEST_COVERAGE_DEFAULT,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->setLayerCompositionType(display,
                        layer, testLayer->getComposition(), &err));
                EXPECT_EQ(err, HWC2_ERROR_BAD_LAYER) << "returned wrong error code";
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_COMPOSITION_TYPE_bad_parameter)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyBadParameter(
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->setLayerCompositionType(display,
                        layer, HWC2_COMPOSITION_INVALID, &err));
                EXPECT_EQ(err, HWC2_ERROR_BAD_PARAMETER) << "returned wrong"
                        " error code";
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_COMPOSITION_TYPE_unsupported)
{
    ASSERT_NO_FATAL_FAILURE(setLayerProperty(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->setLayerCompositionType(display,
                        layer, testLayer->getComposition(), &err));
                EXPECT_TRUE(err == HWC2_ERROR_NONE
                        || err == HWC2_ERROR_UNSUPPORTED)
                         << "returned wrong error code";
            },

            [] (Hwc2TestLayer* testLayer) {
                    return testLayer->advanceComposition();
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_COMPOSITION_TYPE_update)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyUpdate(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->setLayerCompositionType(display,
                        layer, testLayer->getComposition(), &err));
                EXPECT_TRUE(err == HWC2_ERROR_NONE
                        || err == HWC2_ERROR_UNSUPPORTED)
                         << "returned wrong error code";
            },

            [] (Hwc2TestLayer* testLayer) {
                    return testLayer->advanceComposition();
            }
    ));
}

TEST_F(Hwc2Test, SET_CURSOR_POSITION)
{
    ASSERT_NO_FATAL_FAILURE(setLayerProperty(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->setLayerCompositionType(display,
                            layer, HWC2_COMPOSITION_CURSOR, &err));
                EXPECT_EQ(err, HWC2_ERROR_NONE) << "returned wrong error code";

                std::pair<int32_t, int32_t> cursor = testLayer->getCursor();
                EXPECT_NO_FATAL_FAILURE(test->setCursorPosition(display,
                        layer, cursor.first, cursor.second));
            },

            [] (Hwc2TestLayer* testLayer) {
                    return testLayer->advanceCursor();
            }
    ));
}

TEST_F(Hwc2Test, SET_CURSOR_POSITION_bad_display)
{
    hwc2_display_t display;
    hwc2_layer_t layer = 0;
    int32_t x = 0, y = 0;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    ASSERT_NO_FATAL_FAILURE(setCursorPosition(display, layer, x, y, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

TEST_F(Hwc2Test, SET_CURSOR_POSITION_bad_layer)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyBadLayer(HWC2_TEST_COVERAGE_DEFAULT,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                std::pair<int32_t, int32_t> cursor = testLayer->getCursor();
                ASSERT_NO_FATAL_FAILURE(test->setCursorPosition(display,
                        layer, cursor.first, cursor.second, &err));
                EXPECT_EQ(err, HWC2_ERROR_BAD_LAYER) << "returned wrong error code";
            }
    ));
}

TEST_F(Hwc2Test, SET_CURSOR_POSITION_composition_type_unset)
{
    ASSERT_NO_FATAL_FAILURE(setLayerProperty(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                std::pair<int32_t, int32_t> cursor = testLayer->getCursor();
                EXPECT_NO_FATAL_FAILURE(test->setCursorPosition(display,
                        layer, cursor.first, cursor.second));
            },

            [] (Hwc2TestLayer* testLayer) {
                    return testLayer->advanceCursor();
            }
    ));
}

TEST_F(Hwc2Test, SET_CURSOR_POSITION_update)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyUpdate(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->setLayerCompositionType(display,
                        layer, HWC2_COMPOSITION_CURSOR, &err));
                EXPECT_EQ(err, HWC2_ERROR_NONE) << "returned wrong error code";

                std::pair<int32_t, int32_t> cursor = testLayer->getCursor();
                EXPECT_NO_FATAL_FAILURE(test->setCursorPosition(display,
                        layer, cursor.first, cursor.second));
            },

            [] (Hwc2TestLayer* testLayer) {
                    return testLayer->advanceCursor();
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_BLEND_MODE)
{
    ASSERT_NO_FATAL_FAILURE(setLayerProperty(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                EXPECT_NO_FATAL_FAILURE(test->setLayerBlendMode(display, layer,
                        testLayer->getBlendMode()));
            },

            [] (Hwc2TestLayer* testLayer) {
                    return testLayer->advanceBlendMode();
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_BLEND_MODE_bad_layer)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyBadLayer(HWC2_TEST_COVERAGE_DEFAULT,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->setLayerBlendMode(display, layer,
                        testLayer->getBlendMode(), &err));
                EXPECT_EQ(err, HWC2_ERROR_BAD_LAYER) << "returned wrong error code";
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_BLEND_MODE_bad_parameter)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyBadParameter(
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->setLayerBlendMode(display,
                        layer, HWC2_BLEND_MODE_INVALID, &err));
                EXPECT_EQ(err, HWC2_ERROR_BAD_PARAMETER) << "returned wrong"
                        " error code";
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_BLEND_MODE_update)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyUpdate(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                EXPECT_NO_FATAL_FAILURE(test->setLayerBlendMode(display,
                        layer, testLayer->getBlendMode()));
            },

            [] (Hwc2TestLayer* testLayer) {
                    return testLayer->advanceBlendMode();
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_BUFFER)
{
    const std::vector<hwc2_composition_t> compositions = {
            HWC2_COMPOSITION_DEVICE, HWC2_COMPOSITION_CURSOR};

    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs) {
            int32_t width, height;

            ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));
            ASSERT_NO_FATAL_FAILURE(getActiveDimensions(display, &width, &height));
            Hwc2TestLayer testLayer(HWC2_TEST_COVERAGE_COMPLETE, width, height);

            for (auto composition : compositions) {
                do {
                    hwc2_layer_t layer;
                    buffer_handle_t handle;
                    android::base::unique_fd acquireFence;
                    hwc2_error_t err = HWC2_ERROR_NONE;

                    if (testLayer.getBuffer(&handle, &acquireFence) < 0)
                        continue;
                    ASSERT_NO_FATAL_FAILURE(createLayer(display, &layer));

                    ASSERT_NO_FATAL_FAILURE(setLayerCompositionType(display,
                            layer, composition, &err));
                    EXPECT_EQ(err, HWC2_ERROR_NONE) << "returned wrong error code";

                    EXPECT_NO_FATAL_FAILURE(setLayerBuffer(display, layer,
                            handle, acquireFence));

                    ASSERT_NO_FATAL_FAILURE(destroyLayer(display, layer));

                } while (testLayer.advanceBufferArea());
                testLayer.reset();
            }
        }
    }
}

TEST_F(Hwc2Test, SET_LAYER_BUFFER_bad_composition)
{
    const std::vector<hwc2_composition_t> compositions = {
            HWC2_COMPOSITION_CLIENT, HWC2_COMPOSITION_SOLID_COLOR,
            HWC2_COMPOSITION_SIDEBAND};

    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs) {
            int32_t width, height;

            ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));
            ASSERT_NO_FATAL_FAILURE(getActiveDimensions(display, &width, &height));
            Hwc2TestLayer testLayer(HWC2_TEST_COVERAGE_BASIC, width, height);

            for (auto composition : compositions) {
                do {
                    hwc2_layer_t layer;
                    buffer_handle_t handle;
                    android::base::unique_fd acquireFence;
                    hwc2_error_t err = HWC2_ERROR_NONE;

                    if (testLayer.getBuffer(&handle, &acquireFence) < 0)
                        continue;
                    ASSERT_NO_FATAL_FAILURE(createLayer(display, &layer));

                    ASSERT_NO_FATAL_FAILURE(setLayerCompositionType(display,
                            layer, composition, &err));
                    if (composition == HWC2_COMPOSITION_SIDEBAND &&
                            err == HWC2_ERROR_UNSUPPORTED) {
                        EXPECT_NE(composition, HWC2_COMPOSITION_CLIENT)
                                << "returned wrong error code";
                    } else {
                        EXPECT_EQ(err, HWC2_ERROR_NONE) << "returned wrong error code";
                    }

                    EXPECT_NO_FATAL_FAILURE(setLayerBuffer(display, layer,
                            handle, acquireFence));

                    ASSERT_NO_FATAL_FAILURE(destroyLayer(display, layer));

                } while (testLayer.advanceBufferArea());
                testLayer.reset();
            }
        }
    }
}

TEST_F(Hwc2Test, SET_LAYER_BUFFER_bad_layer)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyBadLayer(HWC2_TEST_COVERAGE_DEFAULT,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                buffer_handle_t handle = nullptr;
                android::base::unique_fd acquireFence;
                hwc2_error_t err = HWC2_ERROR_NONE;

                if (testLayer->getBuffer(&handle, &acquireFence) == 0)
                    return;

                ASSERT_NO_FATAL_FAILURE(test->setLayerBuffer(display, layer,
                        handle, acquireFence, &err));
                EXPECT_EQ(err, HWC2_ERROR_BAD_LAYER) << "returned wrong error code";
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_BUFFER_bad_parameter)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyBadParameter(
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer) {

                buffer_handle_t handle = nullptr;
                int32_t acquireFence = -1;
                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->setLayerBuffer(display, layer,
                        handle, acquireFence, &err));
                EXPECT_EQ(err, HWC2_ERROR_BAD_PARAMETER)
                        << "returned wrong error code";
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_BUFFER_update)
{
    const std::vector<hwc2_composition_t> compositions = {
            HWC2_COMPOSITION_DEVICE, HWC2_COMPOSITION_CURSOR};

    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs) {
            int32_t width, height;

            ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));
            ASSERT_NO_FATAL_FAILURE(getActiveDimensions(display, &width, &height));
            Hwc2TestLayer testLayer(HWC2_TEST_COVERAGE_COMPLETE, width, height);

            for (auto composition : compositions) {
                hwc2_layer_t layer;
                buffer_handle_t handle;
                android::base::unique_fd acquireFence;
                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(createLayer(display, &layer));

                do {
                    if (testLayer.getBuffer(&handle, &acquireFence) < 0)
                        continue;

                    ASSERT_NO_FATAL_FAILURE(setLayerCompositionType(display,
                            layer, composition, &err));
                    EXPECT_EQ(err, HWC2_ERROR_NONE) << "returned wrong error code";

                    EXPECT_NO_FATAL_FAILURE(setLayerBuffer(display, layer,
                            handle, acquireFence));

                } while (testLayer.advanceBufferArea());
                testLayer.reset();

                ASSERT_NO_FATAL_FAILURE(destroyLayer(display, layer));
            }
        }
    }
}

TEST_F(Hwc2Test, SET_LAYER_COLOR)
{
    ASSERT_NO_FATAL_FAILURE(setLayerProperty(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->setLayerCompositionType(display,
                            layer, HWC2_COMPOSITION_SOLID_COLOR, &err));
                if (err != HWC2_ERROR_NONE) {
                    EXPECT_EQ(err, HWC2_ERROR_UNSUPPORTED) << "returned wrong"
                            " error code";
                } else {
                    EXPECT_NO_FATAL_FAILURE(test->setLayerColor(display, layer,
                            testLayer->getColor()));
                }
            },

            [] (Hwc2TestLayer* testLayer) {
                    return testLayer->advanceColor();
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_COLOR_bad_layer)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyBadLayer(HWC2_TEST_COVERAGE_DEFAULT,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->setLayerColor(display, layer,
                        testLayer->getColor(), &err));
                EXPECT_EQ(err, HWC2_ERROR_BAD_LAYER) << "returned wrong error code";
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_COLOR_composition_type_unset)
{
    ASSERT_NO_FATAL_FAILURE(setLayerProperty(HWC2_TEST_COVERAGE_BASIC,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                EXPECT_NO_FATAL_FAILURE(test->setLayerColor(display, layer,
                        testLayer->getColor()));
            },

            [] (Hwc2TestLayer* testLayer) {
                    return testLayer->advanceColor();
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_COLOR_update)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyUpdate(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->setLayerCompositionType(display,
                            layer, HWC2_COMPOSITION_SOLID_COLOR, &err));
                if (err != HWC2_ERROR_NONE) {
                    EXPECT_EQ(err, HWC2_ERROR_UNSUPPORTED) << "returned wrong"
                            " error code";
                } else {
                    EXPECT_NO_FATAL_FAILURE(test->setLayerColor(display, layer,
                            testLayer->getColor()));
                }
            },

            [] (Hwc2TestLayer* testLayer) {
                    return testLayer->advanceColor();
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_DATASPACE)
{
    ASSERT_NO_FATAL_FAILURE(setLayerProperty(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                EXPECT_NO_FATAL_FAILURE(test->setLayerDataspace(display, layer,
                        testLayer->getDataspace()));
            },

            [] (Hwc2TestLayer* testLayer) {
                    return testLayer->advanceDataspace();
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_DATASPACE_bad_layer)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyBadLayer(HWC2_TEST_COVERAGE_DEFAULT,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->setLayerDataspace(display, layer,
                        testLayer->getDataspace(), &err));
                EXPECT_EQ(err, HWC2_ERROR_BAD_LAYER) << "returned wrong error code";
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_DATASPACE_update)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyUpdate(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                EXPECT_NO_FATAL_FAILURE(test->setLayerDataspace(display,
                        layer, testLayer->getDataspace()));
            },

            [] (Hwc2TestLayer* testLayer) {
                    return testLayer->advanceDataspace();
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_DISPLAY_FRAME)
{
    ASSERT_NO_FATAL_FAILURE(setLayerProperty(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                EXPECT_NO_FATAL_FAILURE(test->setLayerDisplayFrame(display,
                        layer, testLayer->getDisplayFrame()));
            },

            [] (Hwc2TestLayer* testLayer) {
                    return testLayer->advanceDisplayFrame();
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_DISPLAY_FRAME_bad_layer)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyBadLayer(HWC2_TEST_COVERAGE_DEFAULT,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->setLayerDisplayFrame(display,
                        layer, testLayer->getDisplayFrame(), &err));
                EXPECT_EQ(err, HWC2_ERROR_BAD_LAYER) << "returned wrong error code";
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_DISPLAY_FRAME_update)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyUpdate(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                EXPECT_NO_FATAL_FAILURE(test->setLayerDisplayFrame(display,
                        layer, testLayer->getDisplayFrame()));
            },

            [] (Hwc2TestLayer* testLayer) {
                    return testLayer->advanceDisplayFrame();
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_PLANE_ALPHA)
{
    ASSERT_NO_FATAL_FAILURE(setLayerProperty(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                ASSERT_NO_FATAL_FAILURE(test->setLayerBlendMode(display, layer,
                        testLayer->getBlendMode()));
                EXPECT_NO_FATAL_FAILURE(test->setLayerPlaneAlpha(display, layer,
                        testLayer->getPlaneAlpha()));
            },

            [] (Hwc2TestLayer* testLayer) {
                    if (testLayer->advanceBlendMode())
                        return true;
                    return testLayer->advancePlaneAlpha();
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_PLANE_ALPHA_bad_layer)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyBadLayer(HWC2_TEST_COVERAGE_DEFAULT,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->setLayerPlaneAlpha(display, layer,
                        testLayer->getPlaneAlpha(), &err));
                EXPECT_EQ(err, HWC2_ERROR_BAD_LAYER) << "returned wrong error code";
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_PLANE_ALPHA_update)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyUpdate(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                ASSERT_NO_FATAL_FAILURE(test->setLayerBlendMode(display, layer,
                        testLayer->getBlendMode()));
                EXPECT_NO_FATAL_FAILURE(test->setLayerPlaneAlpha(display, layer,
                        testLayer->getPlaneAlpha()));
            },

            [] (Hwc2TestLayer* testLayer) {
                    if (testLayer->advanceBlendMode())
                        return true;
                    return testLayer->advancePlaneAlpha();
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_SOURCE_CROP)
{
    ASSERT_NO_FATAL_FAILURE(setLayerProperty(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                EXPECT_NO_FATAL_FAILURE(test->setLayerSourceCrop(display, layer,
                        testLayer->getSourceCrop()));
            },

            [] (Hwc2TestLayer* testLayer) {
                    if (testLayer->advanceSourceCrop())
                        return true;
                    return testLayer->advanceBufferArea();
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_SOURCE_CROP_bad_layer)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyBadLayer(HWC2_TEST_COVERAGE_DEFAULT,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->setLayerSourceCrop(display, layer,
                        testLayer->getSourceCrop(), &err));
                EXPECT_EQ(err, HWC2_ERROR_BAD_LAYER) << "returned wrong error code";
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_SOURCE_CROP_update)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyUpdate(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                EXPECT_NO_FATAL_FAILURE(test->setLayerSourceCrop(display, layer,
                        testLayer->getSourceCrop()));
            },

            [] (Hwc2TestLayer* testLayer) {
                    if (testLayer->advanceSourceCrop())
                        return true;
                    return testLayer->advanceBufferArea();
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_SURFACE_DAMAGE)
{
    ASSERT_NO_FATAL_FAILURE(setLayerProperty(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                EXPECT_NO_FATAL_FAILURE(test->setLayerSurfaceDamage(display, layer,
                        testLayer->getSurfaceDamage()));
            },

            [] (Hwc2TestLayer* testLayer) {
                    if (testLayer->advanceSurfaceDamage())
                        return true;
                    return testLayer->advanceBufferArea();
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_SURFACE_DAMAGE_bad_layer)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyBadLayer(HWC2_TEST_COVERAGE_DEFAULT,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->setLayerSurfaceDamage(display, layer,
                        testLayer->getSurfaceDamage(), &err));
                EXPECT_EQ(err, HWC2_ERROR_BAD_LAYER) << "returned wrong error code";
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_SURFACE_DAMAGE_update)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyUpdate(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                EXPECT_NO_FATAL_FAILURE(test->setLayerSurfaceDamage(display, layer,
                        testLayer->getSurfaceDamage()));
            },

            [] (Hwc2TestLayer* testLayer) {
                    if (testLayer->advanceSurfaceDamage())
                        return true;
                    return testLayer->advanceBufferArea();
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_TRANSFORM)
{
    ASSERT_NO_FATAL_FAILURE(setLayerProperty(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                EXPECT_NO_FATAL_FAILURE(test->setLayerTransform(display, layer,
                        testLayer->getTransform()));
            },

            [] (Hwc2TestLayer* testLayer) {
                    return testLayer->advanceTransform();
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_TRANSFORM_bad_layer)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyBadLayer(HWC2_TEST_COVERAGE_DEFAULT,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->setLayerTransform(display, layer,
                        testLayer->getTransform(), &err));
                EXPECT_EQ(err, HWC2_ERROR_BAD_LAYER) << "returned wrong error code";
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_TRANSFORM_update)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyUpdate(HWC2_TEST_COVERAGE_COMPLETE,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* testLayer) {

                EXPECT_NO_FATAL_FAILURE(test->setLayerTransform(display,
                        layer, testLayer->getTransform()));
            },

            [] (Hwc2TestLayer* testLayer) {
                    return testLayer->advanceTransform();
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_VISIBLE_REGION)
{
    const size_t layerCnt = 5;

    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs) {
            int32_t width, height;
            std::vector<hwc2_layer_t> layers;

            ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));
            ASSERT_NO_FATAL_FAILURE(getActiveDimensions(display, &width, &height));

            ASSERT_NO_FATAL_FAILURE(createLayers(display, &layers, layerCnt));
            Hwc2TestLayers testLayers(layers, HWC2_TEST_COVERAGE_BASIC, width,
                    height);

            do {
                for (auto layer : layers)
                    EXPECT_NO_FATAL_FAILURE(setLayerVisibleRegion(display,
                            layer, testLayers.getVisibleRegion(layer)));
            } while (testLayers.advanceVisibleRegions());

            ASSERT_NO_FATAL_FAILURE(destroyLayers(display, &layers));
        }
    }
}

TEST_F(Hwc2Test, SET_LAYER_VISIBLE_REGION_bad_layer)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyBadLayer(HWC2_TEST_COVERAGE_DEFAULT,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* /*testLayer*/) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->setLayerVisibleRegion(display,
                        layer, { }, &err));
                EXPECT_EQ(err, HWC2_ERROR_BAD_LAYER) << "returned wrong error code";
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_Z_ORDER)
{
    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        const size_t layerCnt = 10;

        for (auto config : configs) {
            std::vector<hwc2_layer_t> layers;
            int32_t width, height;

            ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));
            ASSERT_NO_FATAL_FAILURE(getActiveDimensions(display, &width, &height));

            ASSERT_NO_FATAL_FAILURE(createLayers(display, &layers, layerCnt));
            Hwc2TestLayers testLayers(layers, HWC2_TEST_COVERAGE_COMPLETE,
                    width, height);

            for (auto layer : layers)
                EXPECT_NO_FATAL_FAILURE(setLayerZOrder(display, layer,
                        testLayers.getZOrder(layer)));

            ASSERT_NO_FATAL_FAILURE(destroyLayers(display, &layers));
        }
    }
}

TEST_F(Hwc2Test, SET_LAYER_Z_ORDER_bad_layer)
{
    ASSERT_NO_FATAL_FAILURE(setLayerPropertyBadLayer(HWC2_TEST_COVERAGE_DEFAULT,
            [] (Hwc2Test* test, hwc2_display_t display, hwc2_layer_t layer,
                    Hwc2TestLayer* /*testLayer*/) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->setLayerZOrder(display, layer, 0,
                        &err));
                EXPECT_EQ(err, HWC2_ERROR_BAD_LAYER) << "returned wrong error code";
            }
    ));
}

TEST_F(Hwc2Test, SET_LAYER_Z_ORDER_update)
{
    const std::vector<uint32_t> zOrders = { static_cast<uint32_t>(0),
            static_cast<uint32_t>(1), static_cast<uint32_t>(UINT32_MAX / 4),
            static_cast<uint32_t>(UINT32_MAX / 2),
            static_cast<uint32_t>(UINT32_MAX) };

    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs) {
            hwc2_layer_t layer;

            ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));

            ASSERT_NO_FATAL_FAILURE(createLayer(display, &layer));

            for (uint32_t zOrder : zOrders)
                EXPECT_NO_FATAL_FAILURE(setLayerZOrder(display, layer, zOrder));

            ASSERT_NO_FATAL_FAILURE(destroyLayer(display, layer));
        }
    }
}

TEST_F(Hwc2Test, VALIDATE_DISPLAY_basic)
{
    ASSERT_NO_FATAL_FAILURE(displayLayers(HWC2_TEST_COVERAGE_BASIC, 1,
            [] (Hwc2Test* test, hwc2_display_t display,
                    const std::vector<hwc2_layer_t>& layers,
                    const Hwc2TestLayers& /*testLayers*/) {

                uint32_t numTypes, numRequests;
                bool hasChanges = false;

                EXPECT_NO_FATAL_FAILURE(test->validateDisplay(display, &numTypes,
                        &numRequests, &hasChanges));
                if (hasChanges)
                    EXPECT_LE(numTypes, static_cast<uint32_t>(layers.size()))
                            << "wrong number of requests";
            }
    ));
}

TEST_F(Hwc2Test, VALIDATE_DISPLAY_default_5)
{
    ASSERT_NO_FATAL_FAILURE(displayLayers(HWC2_TEST_COVERAGE_DEFAULT, 5,
            [] (Hwc2Test* test, hwc2_display_t display,
                    const std::vector<hwc2_layer_t>& layers,
                    const Hwc2TestLayers& /*testLayers*/) {

                uint32_t numTypes, numRequests;
                bool hasChanges = false;

                EXPECT_NO_FATAL_FAILURE(test->validateDisplay(display, &numTypes,
                        &numRequests, &hasChanges));
                if (hasChanges)
                    EXPECT_LE(numTypes, static_cast<uint32_t>(layers.size()))
                            << "wrong number of requests";
            }
    ));
}

TEST_F(Hwc2Test, VALIDATE_DISPLAY_bad_display)
{
    hwc2_display_t display;
    uint32_t numTypes, numRequests;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    ASSERT_NO_FATAL_FAILURE(validateDisplay(display, &numTypes, &numRequests,
            &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

TEST_F(Hwc2Test, GET_DISPLAY_REQUESTS_basic)
{
    ASSERT_NO_FATAL_FAILURE(displayLayers(HWC2_TEST_COVERAGE_BASIC, 1,
            [] (Hwc2Test* test, hwc2_display_t display,
                    const std::vector<hwc2_layer_t>& layers,
                    const Hwc2TestLayers& /*testLayers*/) {

                uint32_t numTypes, numRequests;
                bool hasChanges = false;

                ASSERT_NO_FATAL_FAILURE(test->validateDisplay(display, &numTypes,
                        &numRequests, &hasChanges));
                if (hasChanges)
                    EXPECT_LE(numTypes, layers.size())
                            << "wrong number of requests";

                EXPECT_NO_FATAL_FAILURE(test->manageRequests(display, layers,
                        numRequests));
            }
    ));
}

TEST_F(Hwc2Test, GET_DISPLAY_REQUESTS_bad_display)
{
    hwc2_display_t display;
    hwc2_display_request_t displayRequests;
    std::vector<hwc2_layer_t> layers;
    std::vector<hwc2_layer_request_t> layerRequests;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    EXPECT_NO_FATAL_FAILURE(getDisplayRequests(display, &displayRequests,
            &layers, &layerRequests, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

TEST_F(Hwc2Test, GET_DISPLAY_REQUESTS_not_validated)
{
    ASSERT_NO_FATAL_FAILURE(displayNonValidatedLayers(5,
            [] (Hwc2Test* test, hwc2_display_t display,
                    std::vector<hwc2_layer_t>* layers) {

                hwc2_display_request_t displayRequests;
                std::vector<hwc2_layer_request_t> layerRequests;
                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->getDisplayRequests(display,
                        &displayRequests, layers, &layerRequests, &err));
                EXPECT_EQ(err, HWC2_ERROR_NOT_VALIDATED)
                        << "returned wrong error code";
            }
    ));
}

TEST_F(Hwc2Test, GET_CHANGED_COMPOSITION_TYPES_basic)
{
    ASSERT_NO_FATAL_FAILURE(displayLayers(HWC2_TEST_COVERAGE_BASIC, 1,
            [] (Hwc2Test* test, hwc2_display_t display,
                    const std::vector<hwc2_layer_t>& layers,
                    const Hwc2TestLayers& testLayers) {

                uint32_t numTypes, numRequests;
                bool hasChanges = false;

                ASSERT_NO_FATAL_FAILURE(test->validateDisplay(display, &numTypes,
                        &numRequests, &hasChanges));
                if (hasChanges)
                    EXPECT_LE(numTypes, layers.size())
                            << "wrong number of requests";

                EXPECT_NO_FATAL_FAILURE(test->manageCompositionChanges(display,
                        testLayers, layers, numTypes));
            }
    ));
}

TEST_F(Hwc2Test, GET_CHANGED_COMPOSITION_TYPES_bad_display)
{
    hwc2_display_t display;
    std::vector<hwc2_layer_t> layers;
    std::vector<hwc2_composition_t> types;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    EXPECT_NO_FATAL_FAILURE(getChangedCompositionTypes(display, &layers,
            &types, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

TEST_F(Hwc2Test, GET_CHANGED_COMPOSITION_TYPES_not_validated)
{
    ASSERT_NO_FATAL_FAILURE(displayNonValidatedLayers(5,
            [] (Hwc2Test* test, hwc2_display_t display,
                    std::vector<hwc2_layer_t>* layers) {

                std::vector<hwc2_composition_t> types;
                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->getChangedCompositionTypes(
                        display, layers, &types, &err));
                EXPECT_EQ(err, HWC2_ERROR_NOT_VALIDATED)
                        << "returned wrong error code";
            }
    ));
}

TEST_F(Hwc2Test, ACCEPT_DISPLAY_CHANGES_basic)
{
    ASSERT_NO_FATAL_FAILURE(displayLayers(HWC2_TEST_COVERAGE_BASIC, 1,
            [] (Hwc2Test* test, hwc2_display_t display,
                    const std::vector<hwc2_layer_t>& layers,
                    const Hwc2TestLayers& testLayers) {

                uint32_t numTypes, numRequests;
                bool hasChanges = false;

                ASSERT_NO_FATAL_FAILURE(test->validateDisplay(display, &numTypes,
                        &numRequests, &hasChanges));
                if (hasChanges)
                    EXPECT_LE(numTypes, layers.size())
                            << "wrong number of requests";

                ASSERT_NO_FATAL_FAILURE(test->manageCompositionChanges(display,
                        testLayers, layers, numTypes));

                EXPECT_NO_FATAL_FAILURE(test->acceptDisplayChanges(display));
            }
    ));
}

TEST_F(Hwc2Test, ACCEPT_DISPLAY_CHANGES_bad_display)
{
    hwc2_display_t display;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    EXPECT_NO_FATAL_FAILURE(acceptDisplayChanges(display, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

TEST_F(Hwc2Test, ACCEPT_DISPLAY_CHANGES_not_validated)
{
    ASSERT_NO_FATAL_FAILURE(displayNonValidatedLayers(5,
            [] (Hwc2Test* test, hwc2_display_t display,
                    std::vector<hwc2_layer_t>* /*layers*/) {

                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(test->acceptDisplayChanges(display, &err));
                EXPECT_EQ(err, HWC2_ERROR_NOT_VALIDATED)
                        << "returned wrong error code";
            }
    ));
}

TEST_F(Hwc2Test, GET_CLIENT_TARGET_SUPPORT)
{
    const android_pixel_format_t format = HAL_PIXEL_FORMAT_RGBA_8888;
    const android_dataspace_t dataspace = HAL_DATASPACE_UNKNOWN;

    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs) {
            int32_t width, height;

            ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));
            ASSERT_NO_FATAL_FAILURE(getActiveDimensions(display, &width, &height));

            ASSERT_NO_FATAL_FAILURE(getClientTargetSupport(display, width,
                    height, format, dataspace));
        }
    }
}

TEST_F(Hwc2Test, GET_CLIENT_TARGET_SUPPORT_bad_display)
{
    const android_pixel_format_t format = HAL_PIXEL_FORMAT_RGBA_8888;
    hwc2_display_t bad_display;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&bad_display));

    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs) {
            int32_t width, height;

            ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));
            ASSERT_NO_FATAL_FAILURE(getActiveDimensions(display, &width, &height));
            Hwc2TestClientTargetSupport testClientTargetSupport(
                    HWC2_TEST_COVERAGE_DEFAULT, width, height);

            do {
                hwc2_error_t err = HWC2_ERROR_NONE;

                const std::pair<int32_t, int32_t> bufferArea =
                        testClientTargetSupport.getBufferArea();
                ASSERT_NO_FATAL_FAILURE(getClientTargetSupport(bad_display,
                        bufferArea.first, bufferArea.second, format,
                        testClientTargetSupport.getDataspace(), &err));
                EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
            } while (testClientTargetSupport.advance());
        }
    }
}

TEST_F(Hwc2Test, GET_CLIENT_TARGET_SUPPORT_unsupported)
{
    const android_pixel_format_t format = HAL_PIXEL_FORMAT_RGBA_8888;

    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs) {
            int32_t width, height;

            ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));
            ASSERT_NO_FATAL_FAILURE(getActiveDimensions(display, &width, &height));
            Hwc2TestClientTargetSupport testClientTargetSupport(
                    HWC2_TEST_COVERAGE_DEFAULT, width, height);

            do {
                hwc2_error_t err = HWC2_ERROR_NONE;

                const std::pair<int32_t, int32_t> bufferArea =
                        testClientTargetSupport.getBufferArea();
                ASSERT_NO_FATAL_FAILURE(getClientTargetSupport(display,
                        bufferArea.first, bufferArea.second, format,
                        testClientTargetSupport.getDataspace(), &err));
                EXPECT_TRUE(err == HWC2_ERROR_NONE
                        || err == HWC2_ERROR_UNSUPPORTED)
                        << "returned wrong error code";
            } while (testClientTargetSupport.advance());
        }
    }
}

TEST_F(Hwc2Test, SET_CLIENT_TARGET_basic)
{
    const android_dataspace_t dataspace = HAL_DATASPACE_UNKNOWN;
    const hwc_region_t damage = { };
    const size_t layerCnt = 1;

    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_ON));

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs) {
            int32_t width, height;
            std::vector<hwc2_layer_t> layers;

            ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));
            ASSERT_NO_FATAL_FAILURE(getActiveDimensions(display, &width, &height));

            ASSERT_NO_FATAL_FAILURE(createLayers(display, &layers, layerCnt));
            Hwc2TestLayers testLayers(layers, HWC2_TEST_COVERAGE_BASIC, width,
                    height);

            if (!testLayers.optimizeLayouts())
                continue;

            Hwc2TestClientTarget testClientTarget;

            do {
                std::set<hwc2_layer_t> clientLayers;
                std::set<hwc2_layer_t> clearLayers;
                uint32_t numTypes, numRequests;
                bool hasChanges, skip;
                bool flipClientTarget;
                buffer_handle_t handle;
                int32_t acquireFence;

                ASSERT_NO_FATAL_FAILURE(setLayerProperties(display, layers,
                        &testLayers, &skip));
                if (skip)
                    continue;

                ASSERT_NO_FATAL_FAILURE(validateDisplay(display, &numTypes,
                        &numRequests, &hasChanges));
                if (hasChanges)
                    EXPECT_LE(numTypes, layers.size())
                            << "wrong number of requests";

                ASSERT_NO_FATAL_FAILURE(manageCompositionChanges(display,
                        testLayers, layers, numTypes, &clientLayers));
                ASSERT_NO_FATAL_FAILURE(manageRequests(display, layers,
                        numRequests, &clearLayers, &flipClientTarget));
                ASSERT_EQ(testClientTarget.getBuffer(testLayers, clientLayers,
                        clearLayers, flipClientTarget, width,
                        height, &handle, &acquireFence), 0);
                EXPECT_NO_FATAL_FAILURE(setClientTarget(display, handle,
                        acquireFence, dataspace, damage));

                if (acquireFence >= 0)
                    close(acquireFence);

                clientLayers.clear();
                clearLayers.clear();

            } while (testLayers.advance());

            ASSERT_NO_FATAL_FAILURE(destroyLayers(display, &layers));
        }

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_OFF));
    }
}

TEST_F(Hwc2Test, SET_CLIENT_TARGET_bad_display)
{
    hwc2_display_t display;
    std::vector<hwc2_layer_t> layers;
    int32_t width = 0, height = 0;
    Hwc2TestLayers testLayers(layers, HWC2_TEST_COVERAGE_DEFAULT, width, height);
    std::set<hwc2_layer_t> clientLayers;
    std::set<hwc2_layer_t> flipClientTargetLayers;
    bool flipClientTarget = true;
    const android_dataspace_t dataspace = HAL_DATASPACE_UNKNOWN;
    const hwc_region_t damage = { };
    buffer_handle_t handle;
    int32_t acquireFence;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    Hwc2TestClientTarget testClientTarget;

    ASSERT_EQ(testClientTarget.getBuffer(testLayers, clientLayers,
            flipClientTargetLayers, flipClientTarget, width, height,
            &handle, &acquireFence), 0);

    EXPECT_NO_FATAL_FAILURE(setClientTarget(display, handle,
            acquireFence, dataspace, damage, &err));

    if (acquireFence >= 0)
        close(acquireFence);

    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_default_1)
{
    const size_t layerCnt = 1;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages;
    bool optimize = false;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_default_2)
{
    const size_t layerCnt = 2;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages;
    bool optimize = false;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_default_3)
{
    const size_t layerCnt = 3;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages;
    bool optimize = false;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_default_4)
{
    const size_t layerCnt = 4;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages;
    bool optimize = false;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_default_5)
{
    const size_t layerCnt = 5;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages;
    bool optimize = false;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_default_6)
{
    const size_t layerCnt = 6;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages;
    bool optimize = false;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_blend_mode_1)
{
    const size_t layerCnt = 1;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages =
            {{HWC2_TEST_BLEND_MODE, HWC2_TEST_COVERAGE_COMPLETE},
            {HWC2_TEST_TRANSFORM, HWC2_TEST_COVERAGE_BASIC},
            {HWC2_TEST_PLANE_ALPHA, HWC2_TEST_COVERAGE_BASIC}};
    bool optimize = false;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_blend_mode_2)
{
    const size_t layerCnt = 2;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages =
            {{HWC2_TEST_BLEND_MODE, HWC2_TEST_COVERAGE_COMPLETE},
            {HWC2_TEST_PLANE_ALPHA, HWC2_TEST_COVERAGE_BASIC}};
    bool optimize = false;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_buffer_1)
{
    const size_t layerCnt = 1;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages =
            {{HWC2_TEST_BUFFER_AREA, HWC2_TEST_COVERAGE_COMPLETE}};
    bool optimize = true;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_color_1)
{
    const size_t layerCnt = 1;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages =
            {{HWC2_TEST_COMPOSITION, HWC2_TEST_COVERAGE_COMPLETE},
            {HWC2_TEST_COLOR, HWC2_TEST_COVERAGE_COMPLETE}};
    bool optimize = true;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_color_2)
{
    const size_t layerCnt = 2;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages =
            {{HWC2_TEST_COMPOSITION, HWC2_TEST_COVERAGE_COMPLETE},
            {HWC2_TEST_DISPLAY_FRAME, HWC2_TEST_COVERAGE_BASIC},
            {HWC2_TEST_COLOR, HWC2_TEST_COVERAGE_COMPLETE}};
    bool optimize = true;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_composition_1)
{
    const size_t layerCnt = 1;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages =
            {{HWC2_TEST_COMPOSITION, HWC2_TEST_COVERAGE_COMPLETE}};
    bool optimize = true;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_cursor_1)
{
    const size_t layerCnt = 1;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages =
            {{HWC2_TEST_COMPOSITION, HWC2_TEST_COVERAGE_COMPLETE},
            {HWC2_TEST_CURSOR, HWC2_TEST_COVERAGE_COMPLETE}};
    bool optimize = true;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_cursor_2)
{
    const size_t layerCnt = 2;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages =
            {{HWC2_TEST_COMPOSITION, HWC2_TEST_COVERAGE_COMPLETE},
            {HWC2_TEST_CURSOR, HWC2_TEST_COVERAGE_COMPLETE},
            {HWC2_TEST_DISPLAY_FRAME, HWC2_TEST_COVERAGE_BASIC}};
    bool optimize = true;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_dataspace_1)
{
    const size_t layerCnt = 1;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages =
            {{HWC2_TEST_DATASPACE, HWC2_TEST_COVERAGE_COMPLETE}};
    bool optimize = true;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_display_frame_1)
{
    const size_t layerCnt = 1;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages =
            {{HWC2_TEST_DISPLAY_FRAME, HWC2_TEST_COVERAGE_COMPLETE}};
    bool optimize = true;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_display_frame_2)
{
    const size_t layerCnt = 2;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages =
            {{HWC2_TEST_DISPLAY_FRAME, HWC2_TEST_COVERAGE_COMPLETE}};
    bool optimize = true;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_display_frame_3)
{
    const size_t layerCnt = 3;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages =
            {{HWC2_TEST_DISPLAY_FRAME, HWC2_TEST_COVERAGE_COMPLETE}};
    bool optimize = true;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_display_frame_4)
{
    const size_t layerCnt = 4;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages =
            {{HWC2_TEST_DISPLAY_FRAME, HWC2_TEST_COVERAGE_COMPLETE}};
    bool optimize = true;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_plane_alpha_1)
{
    const size_t layerCnt = 1;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages =
            {{HWC2_TEST_BLEND_MODE, HWC2_TEST_COVERAGE_BASIC},
            {HWC2_TEST_PLANE_ALPHA, HWC2_TEST_COVERAGE_COMPLETE}};
    bool optimize = false;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_plane_alpha_2)
{
    const size_t layerCnt = 2;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages =
            {{HWC2_TEST_BLEND_MODE, HWC2_TEST_COVERAGE_BASIC},
            {HWC2_TEST_TRANSFORM, HWC2_TEST_COVERAGE_BASIC},
            {HWC2_TEST_PLANE_ALPHA, HWC2_TEST_COVERAGE_COMPLETE}};
    bool optimize = false;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_source_crop_1)
{
    const size_t layerCnt = 1;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages =
            {{HWC2_TEST_DISPLAY_FRAME, HWC2_TEST_COVERAGE_COMPLETE},
            {HWC2_TEST_SOURCE_CROP, HWC2_TEST_COVERAGE_COMPLETE}};
    bool optimize = true;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_source_crop_2)
{
    const size_t layerCnt = 2;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages =
            {{HWC2_TEST_DISPLAY_FRAME, HWC2_TEST_COVERAGE_COMPLETE},
            {HWC2_TEST_SOURCE_CROP, HWC2_TEST_COVERAGE_COMPLETE}};
    bool optimize = true;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}


TEST_F(Hwc2Test, PRESENT_DISPLAY_surface_damage_1)
{
    const size_t layerCnt = 1;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages =
            {{HWC2_TEST_SURFACE_DAMAGE, HWC2_TEST_COVERAGE_COMPLETE}};
    bool optimize = true;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_transform_1)
{
    const size_t layerCnt = 1;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages =
            {{HWC2_TEST_TRANSFORM, HWC2_TEST_COVERAGE_COMPLETE}};
    bool optimize = true;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_transform_2)
{
    const size_t layerCnt = 2;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages =
            {{HWC2_TEST_TRANSFORM, HWC2_TEST_COVERAGE_COMPLETE},
            {HWC2_TEST_DISPLAY_FRAME, HWC2_TEST_COVERAGE_BASIC}};
    bool optimize = true;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_basic_1)
{
    const size_t layerCnt = 1;
    hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_BASIC;
    std::map<hwc2_test_property_t, hwc2_test_coverage_t> coverages;
    bool optimize = true;

    ASSERT_NO_FATAL_FAILURE(presentDisplays(layerCnt, coverage, coverages,
            optimize));
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_bad_display)
{
    hwc2_display_t display;
    int32_t presentFence;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    ASSERT_NO_FATAL_FAILURE(presentDisplay(display, &presentFence, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

TEST_F(Hwc2Test, PRESENT_DISPLAY_not_validated)
{
    const size_t layerCnt = 1;
    const hwc2_test_coverage_t coverage = HWC2_TEST_COVERAGE_DEFAULT;

    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_ON));
        ASSERT_NO_FATAL_FAILURE(enableVsync(display));

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs) {
            int32_t width, height;
            std::vector<hwc2_layer_t> layers;

            ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));
            ASSERT_NO_FATAL_FAILURE(getActiveDimensions(display, &width, &height));

            ASSERT_NO_FATAL_FAILURE(createLayers(display, &layers, layerCnt));
            Hwc2TestLayers testLayers(layers, coverage, width, height);

            do {
                bool skip;
                int32_t presentFence;
                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(setLayerProperties(display, layers,
                        &testLayers, &skip));
                if (skip)
                    continue;

                ASSERT_NO_FATAL_FAILURE(waitForVsync());

                ASSERT_NO_FATAL_FAILURE(presentDisplay(display, &presentFence, &err));
                EXPECT_EQ(err, HWC2_ERROR_NOT_VALIDATED) << "returned wrong error code";

            } while (testLayers.advance());

            ASSERT_NO_FATAL_FAILURE(destroyLayers(display, &layers));
        }

        ASSERT_NO_FATAL_FAILURE(disableVsync(display));
        ASSERT_NO_FATAL_FAILURE(setPowerMode(display, HWC2_POWER_MODE_OFF));
    }
}

TEST_F(Hwc2Test, GET_RELEASE_FENCES_bad_display)
{
    hwc2_display_t display;
    std::vector<hwc2_layer_t> layers;
    std::vector<int32_t> fences;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    ASSERT_NO_FATAL_FAILURE(getReleaseFences(display, &layers, &fences, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

static const std::array<android_color_mode, 9> androidColorModes = {{
    HAL_COLOR_MODE_NATIVE,
    HAL_COLOR_MODE_STANDARD_BT601_625,
    HAL_COLOR_MODE_STANDARD_BT601_625_UNADJUSTED,
    HAL_COLOR_MODE_STANDARD_BT601_525,
    HAL_COLOR_MODE_STANDARD_BT601_525_UNADJUSTED,
    HAL_COLOR_MODE_STANDARD_BT709,
    HAL_COLOR_MODE_DCI_P3,
    HAL_COLOR_MODE_SRGB,
    HAL_COLOR_MODE_ADOBE_RGB,
}};

TEST_F(Hwc2Test, GET_COLOR_MODES)
{
    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs) {
            std::vector<android_color_mode_t> colorModes;

            ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));

            ASSERT_NO_FATAL_FAILURE(getColorModes(display, &colorModes));

            EXPECT_NE(std::count(colorModes.begin(), colorModes.end(),
                    HAL_COLOR_MODE_NATIVE), 0) << "all displays"
                    " must support HAL_COLOR_MODE_NATIVE";

            colorModes.clear();
        }
    }
}

TEST_F(Hwc2Test, GET_COLOR_MODES_bad_display)
{
    hwc2_display_t display;
    std::vector<android_color_mode_t> colorModes;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    ASSERT_NO_FATAL_FAILURE(getColorModes(display, &colorModes, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

TEST_F(Hwc2Test, SET_COLOR_MODES)
{
    const android_color_mode_t colorMode = HAL_COLOR_MODE_NATIVE;

    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (hwc2_config_t config : configs) {
            ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));

            EXPECT_NO_FATAL_FAILURE(setColorMode(display, colorMode));
        }
    }
}

TEST_F(Hwc2Test, SET_COLOR_MODES_bad_display)
{
    hwc2_display_t display;
    const android_color_mode_t colorMode = HAL_COLOR_MODE_NATIVE;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    ASSERT_NO_FATAL_FAILURE(setColorMode(display, colorMode, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

TEST_F(Hwc2Test, SET_COLOR_MODES_bad_parameter)
{
    const android_color_mode_t colorMode = static_cast<android_color_mode_t>(-1);

    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs) {
            hwc2_error_t err = HWC2_ERROR_NONE;

            ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));

            ASSERT_NO_FATAL_FAILURE(setColorMode(display, colorMode, &err));
            EXPECT_EQ(err, HWC2_ERROR_BAD_PARAMETER) << "returned wrong error code";
        }
    }
}

TEST_F(Hwc2Test, SET_COLOR_MODES_unsupported)
{
    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs) {
            ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));

            for (auto colorMode : androidColorModes) {
                hwc2_error_t err = HWC2_ERROR_NONE;

                ASSERT_NO_FATAL_FAILURE(setColorMode(display, colorMode, &err));

                EXPECT_TRUE(err == HWC2_ERROR_NONE || err == HWC2_ERROR_UNSUPPORTED)
                        << "returned wrong error code";
            }
        }
    }
}

TEST_F(Hwc2Test, GET_HDR_CAPABILITIES)
{
    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs) {
            std::vector<android_hdr_t> hdrCapabilities;
            float maxLuminance, maxAverageLuminance, minLuminance;

            ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));

            EXPECT_NO_FATAL_FAILURE(getHdrCapabilities(display, &hdrCapabilities,
                    &maxLuminance, &maxAverageLuminance, &minLuminance));

            if (hdrCapabilities.empty())
                continue;

            EXPECT_GE(maxLuminance, maxAverageLuminance);
            EXPECT_GE(maxAverageLuminance, maxLuminance);

            hdrCapabilities.clear();
        }
    }
}

TEST_F(Hwc2Test, GET_HDR_CAPABILITIES_bad_display)
{
    hwc2_display_t display;
    std::vector<android_hdr_t> hdrCapabilities;
    float maxLuminance, maxAverageLuminance, minLuminance;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    ASSERT_NO_FATAL_FAILURE(getHdrCapabilities(display, &hdrCapabilities,
            &maxLuminance, &maxAverageLuminance, &minLuminance, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

static const std::array<float, 16> identityMatrix = {{
    1.0,  0.0,  0.0,  0.0,
    0.0,  1.0,  0.0,  0.0,
    0.0,  0.0,  1.0,  0.0,
    0.0,  0.0,  0.0,  1.0,
}};

static const std::array<const std::array<float, 16>, 7> exampleMatrices = {{
    identityMatrix,
    {{ 0.0,  0.0,  0.0,  0.0,
       0.0,  0.0,  0.0,  0.0,
       0.0,  0.0,  0.0,  0.0,
       0.0,  0.0,  0.0,  1.0}},
    {{ 2.0,  0.0,  0.0,  0.0,
       0.0,  0.5,  0.0,  0.0,
       0.0,  0.0,  1.5,  0.0,
       0.0,  0.0,  0.0,  1.0}},
    {{ 1.0,  0.0,  0.0,  0.0,
       0.5,  1.0,  0.0,  0.0,
       0.0,  0.0,  1.0,  0.0,
       0.0,  0.0,  0.0,  1.0}},
    {{ 1.0,  0.0,  0.0,  0.0,
       0.0,  1.0,  0.0,  0.0,
       0.0,  0.0,  1.0,  0.0,
       5.0,  2.0,  9.0,  1.0}},
    {{ 1.0,  1.0,  1.0,  0.0,
       1.0,  1.0,  1.0,  0.0,
       1.0,  1.0,  1.0,  0.0,
       1.0,  1.0,  1.0,  1.0}},
    {{ 1.6, -0.5, -0.2,  0.0,
      -0.4,  2.3, -0.3,  0.0,
      -0.7, -0.1,  3.0,  0.0,
       0.9,  0.8,  1.6,  1.0}},
}};

TEST_F(Hwc2Test, SET_COLOR_TRANSFORM)
{
    const android_color_transform_t hint = HAL_COLOR_TRANSFORM_IDENTITY;

    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs) {
            ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));

            EXPECT_NO_FATAL_FAILURE(setColorTransform(display, identityMatrix,
                    hint));
        }
    }
}

TEST_F(Hwc2Test, SET_COLOR_TRANSFORM_bad_display)
{
    hwc2_display_t display;
    android_color_transform_t hint = HAL_COLOR_TRANSFORM_IDENTITY;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    ASSERT_NO_FATAL_FAILURE(setColorTransform(display, identityMatrix, hint,
            &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

TEST_F(Hwc2Test, SET_COLOR_TRANSFORM_bad_parameter)
{
    const android_color_transform_t hint = static_cast<android_color_transform_t>(-1);

    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs) {
            hwc2_error_t err = HWC2_ERROR_NONE;

            ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));

            ASSERT_NO_FATAL_FAILURE(setColorTransform(display, identityMatrix,
                    hint, &err));
            EXPECT_EQ(err, HWC2_ERROR_BAD_PARAMETER) << "returned wrong error code";
        }
    }
}

TEST_F(Hwc2Test, SET_COLOR_TRANSFORM_arbitrary_matrix)
{
    const android_color_transform_t hint = HAL_COLOR_TRANSFORM_ARBITRARY_MATRIX;

    for (auto display : mDisplays) {
        std::vector<hwc2_config_t> configs;

        ASSERT_NO_FATAL_FAILURE(getDisplayConfigs(display, &configs));

        for (auto config : configs) {
            ASSERT_NO_FATAL_FAILURE(setActiveConfig(display, config));

            for (const std::array<float, 16>& matrix : exampleMatrices)
                EXPECT_NO_FATAL_FAILURE(setColorTransform(display, matrix, hint));
        }
    }
}

TEST_F(Hwc2Test, CREATE_DESTROY_VIRTUAL_DISPLAY)
{
    Hwc2TestVirtualDisplay testVirtualDisplay(HWC2_TEST_COVERAGE_COMPLETE);
    hwc2_display_t display;

    do {
        const std::pair<uint32_t, uint32_t>& dimension =
                testVirtualDisplay.getDisplayDimension();
        android_pixel_format_t desiredFormat = HAL_PIXEL_FORMAT_RGBA_8888;
        hwc2_error_t err = HWC2_ERROR_NONE;

        ASSERT_NO_FATAL_FAILURE(createVirtualDisplay(dimension.first,
                dimension.second, &desiredFormat, &display, &err));

        EXPECT_TRUE(err == HWC2_ERROR_NONE || err == HWC2_ERROR_NO_RESOURCES
                || err == HWC2_ERROR_UNSUPPORTED) << "returned wrong error code";
        EXPECT_GE(desiredFormat, 0) << "invalid format";

        if (err == HWC2_ERROR_NONE)
            ASSERT_NO_FATAL_FAILURE(destroyVirtualDisplay(display));

    } while (testVirtualDisplay.advance());
}

TEST_F(Hwc2Test, CREATE_DESTROY_VIRTUAL_DISPLAY_multiple)
{
    Hwc2TestVirtualDisplay testVirtualDisplay(HWC2_TEST_COVERAGE_COMPLETE);
    std::vector<hwc2_display_t> displays;

    do {
        const std::pair<uint32_t, uint32_t>& dimension =
                testVirtualDisplay.getDisplayDimension();
        android_pixel_format_t desiredFormat = HAL_PIXEL_FORMAT_RGBA_8888;
        hwc2_display_t display;
        hwc2_error_t err = HWC2_ERROR_NONE;

        ASSERT_NO_FATAL_FAILURE(createVirtualDisplay(dimension.first,
                dimension.second, &desiredFormat, &display, &err));

        EXPECT_TRUE(err == HWC2_ERROR_NONE || err == HWC2_ERROR_NO_RESOURCES
                || err == HWC2_ERROR_UNSUPPORTED) << "returned wrong error code";
        EXPECT_GE(desiredFormat, 0) << "invalid format";

        if (err == HWC2_ERROR_NONE)
            displays.push_back(display);

    } while (testVirtualDisplay.advance());

    for (hwc2_display_t display : displays)
        EXPECT_NO_FATAL_FAILURE(destroyVirtualDisplay(display));
}

TEST_F(Hwc2Test, DESTROY_VIRTUAL_DISPLAY_bad_display)
{
    hwc2_display_t display;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(getBadDisplay(&display));

    ASSERT_NO_FATAL_FAILURE(destroyVirtualDisplay(display, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_DISPLAY) << "returned wrong error code";
}

TEST_F(Hwc2Test, DESTROY_VIRTUAL_DISPLAY_bad_parameter)
{
    hwc2_display_t display = HWC_DISPLAY_PRIMARY;
    hwc2_error_t err = HWC2_ERROR_NONE;

    ASSERT_NO_FATAL_FAILURE(destroyVirtualDisplay(display, &err));
    EXPECT_EQ(err, HWC2_ERROR_BAD_PARAMETER) << "returned wrong error code";
}

TEST_F(Hwc2Test, GET_MAX_VIRTUAL_DISPLAY_COUNT)
{
    uint32_t maxCnt;

    ASSERT_NO_FATAL_FAILURE(getMaxVirtualDisplayCount(&maxCnt));
}

TEST_F(Hwc2Test, GET_MAX_VIRTUAL_DISPLAY_COUNT_duplicate)
{
    uint32_t maxCnt1, maxCnt2;

    ASSERT_NO_FATAL_FAILURE(getMaxVirtualDisplayCount(&maxCnt1));
    ASSERT_NO_FATAL_FAILURE(getMaxVirtualDisplayCount(&maxCnt2));

    EXPECT_EQ(maxCnt1, maxCnt2) << "returned two different max virtual display"
            " counts";
}

TEST_F(Hwc2Test, GET_MAX_VIRTUAL_DISPLAY_COUNT_create_max)
{
    Hwc2TestVirtualDisplay testVirtualDisplay(HWC2_TEST_COVERAGE_COMPLETE);
    std::vector<hwc2_display_t> displays;
    uint32_t maxCnt;

    ASSERT_NO_FATAL_FAILURE(getMaxVirtualDisplayCount(&maxCnt));

    while (displays.size() < maxCnt) {
        const std::pair<uint32_t, uint32_t>& dimension =
                testVirtualDisplay.getDisplayDimension();
        android_pixel_format_t desiredFormat= HAL_PIXEL_FORMAT_RGBA_8888;
        hwc2_display_t display;
        hwc2_error_t err = HWC2_ERROR_NONE;

        ASSERT_NO_FATAL_FAILURE(createVirtualDisplay(dimension.first,
                dimension.second, &desiredFormat, &display, &err));

        EXPECT_TRUE(err == HWC2_ERROR_NONE || err == HWC2_ERROR_UNSUPPORTED)
                << "returned wrong error code";

        if (err == HWC2_ERROR_NONE)
            displays.push_back(display);

        if (!testVirtualDisplay.advance()) {
            if (displays.empty())
                break;
            testVirtualDisplay.reset();
        }
    }

    for (hwc2_display_t display : displays)
        EXPECT_NO_FATAL_FAILURE(destroyVirtualDisplay(display));
}

TEST_F(Hwc2Test, SET_OUTPUT_BUFFER)
{
    Hwc2TestVirtualDisplay testVirtualDisplay(HWC2_TEST_COVERAGE_COMPLETE);

    do {
        hwc2_display_t display;
        buffer_handle_t handle;
        android::base::unique_fd acquireFence;
        hwc2_error_t err = HWC2_ERROR_NONE;

        const std::pair<uint32_t, uint32_t>& dimension =
                testVirtualDisplay.getDisplayDimension();
        android_pixel_format_t desiredFormat = HAL_PIXEL_FORMAT_RGBA_8888;

        ASSERT_NO_FATAL_FAILURE(createVirtualDisplay(dimension.first,
                dimension.second, &desiredFormat, &display, &err));

        EXPECT_TRUE(err == HWC2_ERROR_NONE || err == HWC2_ERROR_NO_RESOURCES
                || err == HWC2_ERROR_UNSUPPORTED)
                << "returned wrong error code";

        if (err != HWC2_ERROR_NONE)
            continue;

        if (testVirtualDisplay.getBuffer(&handle, &acquireFence) >= 0)
            EXPECT_NO_FATAL_FAILURE(setOutputBuffer(display, handle,
                    acquireFence));

        ASSERT_NO_FATAL_FAILURE(destroyVirtualDisplay(display));

    } while (testVirtualDisplay.advance());
}

TEST_F(Hwc2Test, SET_OUTPUT_BUFFER_bad_display)
{
    Hwc2TestVirtualDisplay testVirtualDisplay(HWC2_TEST_COVERAGE_COMPLETE);

    for (auto display : mDisplays) {
        do {
            buffer_handle_t handle;
            android::base::unique_fd acquireFence;
            hwc2_error_t err = HWC2_ERROR_NONE;

            if (testVirtualDisplay.getBuffer(&handle, &acquireFence) < 0)
                continue;

            ASSERT_NO_FATAL_FAILURE(setOutputBuffer(display, handle,
                    acquireFence, &err));
            EXPECT_TRUE(err == HWC2_ERROR_BAD_DISPLAY
                    || err == HWC2_ERROR_UNSUPPORTED)
                    << "returned wrong error code";

        } while (testVirtualDisplay.advance());
    }
}

TEST_F(Hwc2Test, SET_OUTPUT_BUFFER_bad_parameter)
{
    Hwc2TestVirtualDisplay testVirtualDisplay(HWC2_TEST_COVERAGE_COMPLETE);

    do {
        const std::pair<uint32_t, uint32_t>& dimension =
                testVirtualDisplay.getDisplayDimension();
        hwc2_display_t display;
        android_pixel_format_t desiredFormat = HAL_PIXEL_FORMAT_RGBA_8888;
        buffer_handle_t handle = nullptr;
        uint32_t releaseFence = -1;
        hwc2_error_t err = HWC2_ERROR_NONE;

        ASSERT_NO_FATAL_FAILURE(createVirtualDisplay(dimension.first,
                dimension.second, &desiredFormat, &display, &err));

        EXPECT_TRUE(err == HWC2_ERROR_NONE || err == HWC2_ERROR_NO_RESOURCES
                || err == HWC2_ERROR_UNSUPPORTED);

        if (err != HWC2_ERROR_NONE)
            continue;

        ASSERT_NO_FATAL_FAILURE(setOutputBuffer(display, handle, releaseFence,
                &err));
        EXPECT_EQ(err, HWC2_ERROR_BAD_PARAMETER)
                << "returned wrong error code";

        if (err == HWC2_ERROR_NONE)
            ASSERT_NO_FATAL_FAILURE(destroyVirtualDisplay(display));

    } while (testVirtualDisplay.advance());
}

TEST_F(Hwc2Test, SET_OUTPUT_BUFFER_unsupported)
{
    for (auto display : mDisplays) {
        Hwc2TestVirtualDisplay testVirtualDisplay(HWC2_TEST_COVERAGE_COMPLETE);

        do {
            buffer_handle_t handle;
            android::base::unique_fd acquireFence;
            hwc2_error_t err = HWC2_ERROR_NONE;

            if (testVirtualDisplay.getBuffer(&handle, &acquireFence) < 0)
                continue;

            ASSERT_NO_FATAL_FAILURE(setOutputBuffer(display, handle,
                    acquireFence, &err));
            EXPECT_EQ(err, HWC2_ERROR_UNSUPPORTED) << "returned wrong error code";

        } while (testVirtualDisplay.advance());
    }
}
