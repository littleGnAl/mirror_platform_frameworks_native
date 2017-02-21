/* * Copyright (C) 2016 The Android Open Source Project
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

#include <sstream>

#include "Hwc2TestLayers.h"

Hwc2TestLayers::Hwc2TestLayers(const std::vector<hwc2_layer_t>& layers,
        hwc2_test_coverage_t coverage, int32_t displayWidth,
        int32_t displayHeight)
    : mDisplayWidth(displayWidth),
      mDisplayHeight(displayHeight)
{
    for (auto layer : layers)
        mTestLayers.emplace(std::piecewise_construct,
                std::forward_as_tuple(layer), std::forward_as_tuple(coverage,
                displayWidth, displayHeight));

    /* Iterate over the layers in order and assign z orders in the same order.
     * This allows us to iterate over z orders in the same way when computing
     * visible regions */
    uint32_t nextZOrder = layers.size();

    for (auto& testLayer : mTestLayers)
        testLayer.second.setZOrder(nextZOrder--);

    setVisibleRegions();
}

std::string Hwc2TestLayers::dump() const
{
    std::stringstream dmp;
    for (auto& testLayer : mTestLayers)
        dmp << testLayer.second.dump();
    return dmp.str();
}

void Hwc2TestLayers::reset()
{
    for (auto& testLayer : mTestLayers)
        testLayer.second.reset();
    setVisibleRegions();
}

bool Hwc2TestLayers::advance()
{
    auto itr = mTestLayers.begin();
    bool optimized;

    while (itr != mTestLayers.end()) {
        if (itr->second.advance()) {
            optimized = setVisibleRegions();
            if (!mOptimize || optimized)
                return true;
            itr = mTestLayers.begin();
        } else {
            itr->second.reset();
            ++itr;
        }
    }
    return false;
}

bool Hwc2TestLayers::advanceVisibleRegions()
{
    auto itr = mTestLayers.begin();
    bool optimized;

    while (itr != mTestLayers.end()) {
        if (itr->second.advanceVisibleRegion()) {
            optimized = setVisibleRegions();
            if (!mOptimize || optimized)
                return true;
            itr = mTestLayers.begin();
        } else {
            itr->second.reset();
            ++itr;
        }
    }
    return false;
}

/* Removes layouts that do not cover the entire display.
 * Also removes layouts where a layer is completely blocked from view.
 */
bool Hwc2TestLayers::optimizeLayouts()
{
    mOptimize = true;

    if (setVisibleRegions())
        return true;
    return advance();
}

bool Hwc2TestLayers::contains(hwc2_layer_t layer) const
{
    return mTestLayers.count(layer) != 0;
}

int Hwc2TestLayers::getBuffer(hwc2_layer_t layer, buffer_handle_t* outHandle,
        int32_t* outAcquireFence)
{
    return mTestLayers.find(layer)->second.getBuffer(outHandle,
            outAcquireFence);
}

hwc2_blend_mode_t Hwc2TestLayers::getBlendMode(hwc2_layer_t layer) const
{
    return mTestLayers.find(layer)->second.getBlendMode();
}

std::pair<int32_t, int32_t> Hwc2TestLayers::getBufferArea(
        hwc2_layer_t layer) const
{
    return mTestLayers.find(layer)->second.getBufferArea();
}

hwc_color_t Hwc2TestLayers::getColor(hwc2_layer_t layer) const
{
    return mTestLayers.find(layer)->second.getColor();
}

hwc2_composition_t Hwc2TestLayers::getComposition(hwc2_layer_t layer) const
{
    return mTestLayers.find(layer)->second.getComposition();
}

std::pair<int32_t, int32_t> Hwc2TestLayers::getCursor(hwc2_layer_t layer) const
{
    return mTestLayers.find(layer)->second.getCursor();
}

android_dataspace_t Hwc2TestLayers::getDataspace(hwc2_layer_t layer) const
{
    return mTestLayers.find(layer)->second.getDataspace();
}

hwc_rect_t Hwc2TestLayers::getDisplayFrame(hwc2_layer_t layer) const
{
    return mTestLayers.find(layer)->second.getDisplayFrame();
}

float Hwc2TestLayers::getPlaneAlpha(hwc2_layer_t layer) const
{
    return mTestLayers.find(layer)->second.getPlaneAlpha();
}

hwc_frect_t Hwc2TestLayers::getSourceCrop(hwc2_layer_t layer) const
{
    return mTestLayers.find(layer)->second.getSourceCrop();
}

hwc_region_t Hwc2TestLayers::getSurfaceDamage(hwc2_layer_t layer) const
{
    return mTestLayers.find(layer)->second.getSurfaceDamage();
}

hwc_transform_t Hwc2TestLayers::getTransform(hwc2_layer_t layer) const
{
    return mTestLayers.find(layer)->second.getTransform();
}

hwc_region_t Hwc2TestLayers::getVisibleRegion(hwc2_layer_t layer) const
{
    return mTestLayers.find(layer)->second.getVisibleRegion();
}

uint32_t Hwc2TestLayers::getZOrder(hwc2_layer_t layer) const
{
    return mTestLayers.find(layer)->second.getZOrder();
}

bool Hwc2TestLayers::setVisibleRegions()
{
    /* The region of the display that is covered by layers above the current
     * layer */
    android::Region aboveOpaqueLayers;

    bool optimized = true;

    /* Iterate over test layers from max z order to min z order. */
    for (auto& testLayer : mTestLayers) {
        android::Region visibleRegion;

        /* Set the visible region of this layer */
        if (testLayer.second.getComposition() != HWC2_COMPOSITION_CURSOR) {
            const auto displayFrame = testLayer.second.getDisplayFrame();

            visibleRegion.set(android::Rect(displayFrame.left, displayFrame.top,
                    displayFrame.right, displayFrame.bottom));
        } else {
            const auto bufferArea = testLayer.second.getBufferArea();

            visibleRegion.set(android::Rect(0, 0, bufferArea.first,
                    bufferArea.second));
        }

        /* Remove the area covered by opaque layers above this layer
         * from this layer's visible region */
        visibleRegion.subtractSelf(aboveOpaqueLayers);

        testLayer.second.setVisibleRegion(visibleRegion);

        if (visibleRegion.isEmpty())
            optimized = false;

        /* If this layer is opaque, store the region it covers */
        if (testLayer.second.getPlaneAlpha() == 1.0f)
            aboveOpaqueLayers.orSelf(visibleRegion);
    }

    if (!aboveOpaqueLayers.isRect())
        return false;

    const auto rect = aboveOpaqueLayers.begin();
    if (rect->left != 0 || rect->top != 0 || rect->right != mDisplayWidth
            || rect->bottom != mDisplayHeight)
        return false;

    return optimized;
}
