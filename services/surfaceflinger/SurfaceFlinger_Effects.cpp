/*
 * Copyright (C) 2019 Samsung Electronics
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

#include "BufferLayer.h"
#include "DisplayDevice.h"
#include "Effects/EffectController.h"
#include "SurfaceFlinger.h"
#include "inttypes.h"

namespace android {

void SurfaceFlinger::refreshLayerEffects() {
    for (size_t dpy = 0; dpy < mDisplays.size(); dpy++) {
        const sp<DisplayDevice>& hw(mDisplays[dpy]);
        Vector<sp<Layer>> layersSortedByZ = hw->getVisibleLayersSortedByZ();
        // S-Browser fix
        sp<Layer> lastLayer;
        if (hw->getEffectController()->prepareCommon(layersSortedByZ)) {
            invalidateHwcGeometry();
        }

        sp<EffectController> effectController = hw->getEffectController();
        const Vector<sp<Layer>>& vec(hw->getVisibleLayersSortedByZ());
        if (CC_UNLIKELY(effectController->prepare(vec))) {
            invalidateHwcGeometry();
        }
        if (CC_UNLIKELY(mGeometryInvalid)) {
            Vector<sp<Layer>> currentVisibleLayersForHwc;
            currentVisibleLayersForHwc.reserve(vec.size());
            for (size_t i = 0; i < vec.size(); ++i) {
                const sp<Layer>& layer = vec[i];
                if (!effectController->notInRender(layer)) {
                    currentVisibleLayersForHwc.add(layer);
                }
            }
            hw->setVisibleLayersSortedByZForHwc(currentVisibleLayersForHwc);
        }
    }

    for (size_t dpy = 0; dpy < mDisplays.size(); dpy++) {
        const sp<DisplayDevice>& hw(mDisplays[dpy]);
        int existScreenshotSurface = false;
        const Vector<sp<Layer>>& layersSortedByZ = hw->getVisibleLayersSortedByZ();
        /*for (const sp<Layer>& layer : layersSortedByZ) {
            if (layer->isScreenshotSurface())
                existScreenshotSurface = true;
        }*/
        if (!existScreenshotSurface) hw->getEffectController()->prepareCompleted(layersSortedByZ);
    }
}

bool SurfaceFlinger::processAnimations() {
    const HWComposer& hwc = getHwComposer();

    bool anychange = false;
    bool animActive = false;
    nsecs_t timestamp = hwc.getRefreshTimestamp(HWC_DISPLAY_PRIMARY);
    nsecs_t time_diff = (mLastAnimationTimestamp == -1) ? 0 : timestamp - mLastAnimationTimestamp;

    mDrawingState.traverseInZOrder([&](Layer* layer) {
        if (layer->hasEffect()) { // Run the animation
            animActive |= layer->getEffect()->isAnimationRunning();
        }
    });

    // Run the animations
    while (time_diff > EFFECTS_FRAME_LENGTH_NANOS / 2) {
        mDrawingState.traverseInZOrder([&](Layer* layer) {
            if (layer->hasEffect()) { // Run the animation
                anychange |= layer->getEffect()->advanceAnimation();
            }
        });

        time_diff -= EFFECTS_FRAME_LENGTH_NANOS;
    }

    if (animActive) { // There has not been a change, but we force transaction to keep running for
                      // the next frame
        mLastAnimationTimestamp = timestamp;
        signalTransaction();
    } else {
        if (mLastAnimationTimestamp !=
            -1) { // In order to render the result when the animation stops
            anychange = true;
        }
        mLastAnimationTimestamp = -1;
    }

    return anychange;
}

void SurfaceFlinger::prepareEffectsForCapture(EffectController* eC, Rect sourceCrop,
                                              uint32_t reqWidth, uint32_t reqHeight,
                                              uint32_t reqRaHeight,
                                              TraverseLayersFunction traverseLayers,
                                              Transform::orientation_flags rotation) {
    eC->setCaptureParams(reqWidth, reqHeight, sourceCrop, reqRaHeight, rotation);
    Vector<sp<Layer>> tempLayersSortedByZ;
    traverseLayers([&](Layer* layer) { tempLayersSortedByZ.add(layer); });

    eC->prepareCommon(tempLayersSortedByZ);
    if (eC->prepare(tempLayersSortedByZ)) {
        invalidateHwcGeometry();
    }
    eC->prepareCompleted(tempLayersSortedByZ);
}

static String8 getFormatStr(PixelFormat format) {
    switch (format) {
        case PIXEL_FORMAT_RGBA_8888:
            return String8("RGBA_8888");
        case PIXEL_FORMAT_RGBX_8888:
            return String8("RGBx_8888");
        case PIXEL_FORMAT_RGB_888:
            return String8("RGB_888");
        case PIXEL_FORMAT_RGB_565:
            return String8("RGB_565");
        case PIXEL_FORMAT_BGRA_8888:
            return String8("BGRA_8888");
        case HAL_PIXEL_FORMAT_IMPLEMENTATION_DEFINED:
            return String8("ImplDef");
        default:
            String8 result;
            result.appendFormat("? %08x", format);
            return result;
    }
}

void SurfaceFlinger::dumpEffects(String8& result) const {
    sp<const DisplayDevice> hw(getDefaultDisplayDeviceLocked());

    Vector<sp<Layer>> layersSortedByZ = hw->getVisibleLayersSortedByZ();
    const size_t count = layersSortedByZ.size();

    bool effectIsPresent = false;
    for (size_t i = 0; i < count; i++) {
        if (layersSortedByZ[i]->hasEffect()) {
            effectIsPresent = true;
            break;
        }
    }

    if (!effectIsPresent) {
        return;
    }

    result.appendFormat("SurfaceFlinger Effects:\n");
    result.appendFormat("  numHwLayers=%zu\n", count);

    result.append("    handle  | tr |   format    |     source crop (l,t,r,b)      | eff | pix | "
                  "out | trg | reu | name \n"
                  "------------+----+-------------+--------------------------------+-----+-----+---"
                  "--+-----+-----+-----+------\n");
    //      " __________ | __ | ___________ |_____._,_____._,_____._,_____._ | ___ | ___ | ___ | ___
    //      | ___ | ___...
    for (size_t i = 0; i < count; i++) {
        const sp<Layer>& layer(layersSortedByZ[i]);
        int32_t format = layer->getActiveBuffer() != nullptr
                ? layer->getActiveBuffer()->getPixelFormat()
                : -1;
        String8 name = layer->getName();
        void* nativeBuffer = layer->getActiveBuffer() != nullptr
                ? layer->getActiveBuffer()->getNativeBuffer()
                : nullptr;
        uint32_t transform = layer->getCurrentState().active.transform.getOrientation();
        FloatRect sourceCropf = layer->computeCropDebug(hw);

        String8 formatStr = getFormatStr(format);

        const bool hasEffect = layer->hasEffect();
        PixEffectType pixEffect =
                hasEffect ? layer->getEffect()->getPixType() : PixEffectType::NO_PIXEFFECT;
        EffectOutput effectOutput =
                hasEffect ? layer->getEffect()->getOutput() : EffectOutput::SCREEN;
        EffectTarget effectTarget =
                hasEffect ? layer->getEffect()->getTarget() : EffectTarget::SELF;
        bool reuseFBOCompositionDebug =
                hasEffect && layer->getEffect()->getReuseFBOCompositionDebug();

        result.appendFormat(" %08" PRIxPTR " | %02x | %-11s |%7.1f,%7.1f,%7.1f,%7.1f |  %02u |  "
                                           "%02u |  %02u |  %02u |  %02u | %s\n",
                            intptr_t(nativeBuffer), transform, formatStr.string(), sourceCropf.left,
                            sourceCropf.top, sourceCropf.right, sourceCropf.bottom,
                            (uint32_t)hasEffect, (uint32_t)pixEffect, (uint32_t)effectOutput,
                            (uint32_t)effectTarget, (uint32_t)reuseFBOCompositionDebug,
                            name.string());
    }

    result.append("\n\n");
}

} // namespace android
