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

#include <sstream>

#include "Hwc2TestLayer.h"

hwc2_test_coverage_t getCoverage(hwc2_test_property_t property,
        hwc2_test_coverage_t coverage, const std::map<hwc2_test_property_t,
        hwc2_test_coverage_t>& coverageExceptions)
{
    auto exception = coverageExceptions.find(property);
    return (exception != coverageExceptions.end())? exception->second : coverage;
}

Hwc2TestLayer::Hwc2TestLayer(hwc2_test_coverage_t coverage,
        int32_t displayWidth, int32_t displayHeight)
    : Hwc2TestLayer(coverage, displayWidth, displayHeight,
            std::map<hwc2_test_property_t, hwc2_test_coverage_t>()) { }

Hwc2TestLayer::Hwc2TestLayer(hwc2_test_coverage_t coverage,
        int32_t displayWidth, int32_t displayHeight, const std::map<
        hwc2_test_property_t, hwc2_test_coverage_t>& coverageExceptions)
    : mBlendMode(getCoverage(HWC2_TEST_BLEND_MODE, coverage,
           coverageExceptions)),
      mBufferArea(getCoverage(HWC2_TEST_BUFFER_AREA, coverage,
           coverageExceptions), displayWidth, displayHeight),
      mColor(getCoverage(HWC2_TEST_COLOR, coverage, coverageExceptions)),
      mComposition(getCoverage(HWC2_TEST_COMPOSITION, coverage,
           coverageExceptions)),
      mCursor(getCoverage(HWC2_TEST_CURSOR, coverage, coverageExceptions),
           displayWidth, displayHeight),
      mDataspace(getCoverage(HWC2_TEST_DATASPACE, coverage, coverageExceptions)),
      mDisplayFrame(getCoverage(HWC2_TEST_DISPLAY_FRAME, coverage,
           coverageExceptions), displayWidth, displayHeight),
      mPlaneAlpha(getCoverage(HWC2_TEST_PLANE_ALPHA, coverage,
           coverageExceptions)),
      mSourceCrop(getCoverage(HWC2_TEST_SOURCE_CROP, coverage,
           coverageExceptions)),
      mSurfaceDamage(getCoverage(HWC2_TEST_SURFACE_DAMAGE, coverage,
           coverageExceptions)),
      mTransform(getCoverage(HWC2_TEST_TRANSFORM, coverage, coverageExceptions))
{
    mBufferArea.setDependent(&mBuffer);
    mBufferArea.setDependent(&mSourceCrop);
    mBufferArea.setDependent(&mSurfaceDamage);
}

std::string Hwc2TestLayer::dump() const
{
    std::stringstream dmp;

    dmp << "layer: \n";

    for (auto property : mProperties)
        dmp << property->dump();

    dmp << mVisibleRegion.dump();
    dmp << "\tz order: " << mZOrder << "\n";

    return dmp.str();
}

int Hwc2TestLayer::getBuffer(buffer_handle_t* outHandle,
        android::base::unique_fd* outAcquireFence)
{
    int32_t acquireFence;
    int ret = mBuffer.get(outHandle, &acquireFence);
    outAcquireFence->reset(acquireFence);
    return ret;
}

int Hwc2TestLayer::getBuffer(buffer_handle_t* outHandle,
        int32_t* outAcquireFence)
{
    return mBuffer.get(outHandle, outAcquireFence);
}

void Hwc2TestLayer::setZOrder(uint32_t zOrder)
{
    mZOrder = zOrder;
}

void Hwc2TestLayer::setVisibleRegion(const android::Region& region)
{
    return mVisibleRegion.set(region);
}

void Hwc2TestLayer::reset()
{
    mVisibleRegion.release();

    for (auto property : mProperties)
        property->reset();
}

bool Hwc2TestLayer::advance()
{
    for (auto property : mProperties)
        if (property->isSupported(mComposition.get()))
            if (property->advance())
                return true;
    return false;
}

hwc2_blend_mode_t Hwc2TestLayer::getBlendMode() const
{
    return mBlendMode.get();
}

std::pair<int32_t, int32_t> Hwc2TestLayer::getBufferArea() const
{
    return mBufferArea.get();
}

hwc_color_t Hwc2TestLayer::getColor() const
{
    return mColor.get();
}

hwc2_composition_t Hwc2TestLayer::getComposition() const
{
    return mComposition.get();
}

std::pair<int32_t, int32_t> Hwc2TestLayer::getCursor() const
{
    return mCursor.get();
}

android_dataspace_t Hwc2TestLayer::getDataspace() const
{
    return mDataspace.get();
}

hwc_rect_t Hwc2TestLayer::getDisplayFrame() const
{
    return mDisplayFrame.get();
}

float Hwc2TestLayer::getPlaneAlpha() const
{
    return mPlaneAlpha.get();
}

hwc_frect_t Hwc2TestLayer::getSourceCrop() const
{
    return mSourceCrop.get();
}

hwc_region_t Hwc2TestLayer::getSurfaceDamage() const
{
    return mSurfaceDamage.get();
}

hwc_transform_t Hwc2TestLayer::getTransform() const
{
    return mTransform.get();
}

hwc_region_t Hwc2TestLayer::getVisibleRegion() const
{
    return mVisibleRegion.get();
}

uint32_t Hwc2TestLayer::getZOrder() const
{
    return mZOrder;
}

bool Hwc2TestLayer::advanceBlendMode()
{
    return mBlendMode.advance();
}

bool Hwc2TestLayer::advanceBufferArea()
{
    return mBufferArea.advance();
}

bool Hwc2TestLayer::advanceColor()
{
    return mColor.advance();
}

bool Hwc2TestLayer::advanceComposition()
{
    return mComposition.advance();
}

bool Hwc2TestLayer::advanceCursor()
{
    return mCursor.advance();
}

bool Hwc2TestLayer::advanceDataspace()
{
    return mDataspace.advance();
}

bool Hwc2TestLayer::advanceDisplayFrame()
{
    return mDisplayFrame.advance();
}

bool Hwc2TestLayer::advancePlaneAlpha()
{
    return mPlaneAlpha.advance();
}

bool Hwc2TestLayer::advanceSourceCrop()
{
    return mSourceCrop.advance();
}

bool Hwc2TestLayer::advanceSurfaceDamage()
{
    return mSurfaceDamage.advance();
}

bool Hwc2TestLayer::advanceTransform()
{
    return mTransform.advance();
}

bool Hwc2TestLayer::advanceVisibleRegion()
{
    if (mPlaneAlpha.advance())
        return true;
    return mDisplayFrame.advance();
}
