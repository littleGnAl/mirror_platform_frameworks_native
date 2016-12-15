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

Hwc2TestLayer::Hwc2TestLayer(Hwc2TestCoverage coverage, int32_t displayWidth,
        int32_t displayHeight, uint32_t zOrder)
    : mBlendMode(coverage),
      mColor(coverage),
      mComposition(coverage),
      mDataspace(coverage),
      mDisplayFrame(coverage, displayWidth, displayHeight),
      mPlaneAlpha(coverage),
      mTransform(coverage),
      mZOrder(zOrder) { }

std::string Hwc2TestLayer::dump() const
{
    std::stringstream dmp;

    dmp << "layer: \n";

    for (auto property : mProperties) {
        dmp << property->dump();
    }

    dmp << "\tz order: " << mZOrder << "\n";

    return dmp.str();
}

void Hwc2TestLayer::reset()
{
    for (auto property : mProperties) {
        property->reset();
    }
}

hwc2_blend_mode_t Hwc2TestLayer::getBlendMode() const
{
    return mBlendMode.get();
}

hwc_color_t Hwc2TestLayer::getColor() const
{
    return mColor.get();
}

hwc2_composition_t Hwc2TestLayer::getComposition() const
{
    return mComposition.get();
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

hwc_transform_t Hwc2TestLayer::getTransform() const
{
    return mTransform.get();
}

uint32_t Hwc2TestLayer::getZOrder() const
{
    return mZOrder;
}

bool Hwc2TestLayer::advanceBlendMode()
{
    return mBlendMode.advance();
}

bool Hwc2TestLayer::advanceColor()
{
    return mColor.advance();
}

bool Hwc2TestLayer::advanceComposition()
{
    return mComposition.advance();
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

bool Hwc2TestLayer::advanceTransform()
{
    return mTransform.advance();
}
