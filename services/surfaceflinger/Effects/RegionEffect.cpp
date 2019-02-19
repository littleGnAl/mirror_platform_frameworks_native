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

#include "RegionEffect.h"
#include "DisplayDevice.h"
#include "EffectController.h"
#include "Layer.h"
#include "RenderEngine/EffectsRenderEngine.h"
#include "SurfaceFlinger.h"

namespace android {
void RegionConfig::configure(bool enabled, int type, vec2 pos, vec2 size, vec2 factor, float tsize,
                             bool inv) {
    // settters (dont need any special stuff)
    mEnabled = enabled;
    mType = type;
    mPos = pos;
    mSize = size;
    mFactor = factor;
    mTsize = tsize;
    mInvert = inv;
}

void RegionEffect::setup(EffectController& controller, const Layer& /*layer*/) {
    float posx = RegionEffect::DEF_X;
    float posy = RegionEffect::DEF_Y;
    float sizex = RegionEffect::DEF_XSize;
    float sizey = RegionEffect::DEF_YSize;
    float factorx = RegionEffect::DEF_XFactor;
    float factory = RegionEffect::DEF_YFactor;
    float tsize = RegionEffect::DEF_TSize;
    int type = RegionEffect::DEF_Type;
    bool invert = RegionEffect::DEF_Invert;

    if (mAnimator != NULL) {
        // Take the values from the animator (if they are there)
        if (mAnimator->hasParam(kAnimRegionPosX)) {
            posx = mAnimator->getParam(kAnimRegionPosX);
        }
        if (mAnimator->hasParam(kAnimRegionPosY)) {
            posy = mAnimator->getParam(kAnimRegionPosY);
        }
        if (mAnimator->hasParam(kAnimRegionSizeX)) {
            sizex = mAnimator->getParam(kAnimRegionSizeX);
        }
        if (mAnimator->hasParam(kAnimRegionSizeY)) {
            sizey = mAnimator->getParam(kAnimRegionSizeY);
        }
        if (mAnimator->hasParam(kAnimRegionFactorX)) {
            factorx = mAnimator->getParam(kAnimRegionFactorX);
        }
        if (mAnimator->hasParam(kAnimRegionFactorY)) {
            factory = mAnimator->getParam(kAnimRegionFactorY);
        }
        if (mAnimator->hasParam(kAnimRegionSizeT)) {
            tsize = mAnimator->getParam(kAnimRegionSizeT);
        }
        if (mAnimator->hasParam(kAnimRegionType)) {
            type = (int)mAnimator->getParam(kAnimRegionType);
        }
        if (mAnimator->hasParam(kAnimRegionInvert)) {
            invert = mAnimator->getParam(kAnimRegionInvert);
        }
    }

    sizex = std::max(0.f, sizex);
    sizey = std::max(0.f, sizey);

    const DisplayDevice& hw = controller.getDisplayDevice();

    const Transform& tr(hw.getTransform());
    const vec2 deviceSize(hw.getWidth(), hw.getHeight());

    mPos = tr.transform(posx, posy) / deviceSize;
    mPos.y = 1.0f - mPos.y;

    Rect sizeR = tr.transform(Rect((int)(sizex + .5f), (int)(sizey + .5f)));
    mSize = vec2(sizeR.getWidth(), sizeR.getHeight()) / deviceSize;

    mFactor = vec2(factorx, factory);
    mTsize = tsize;
    mType = type;
    mInvert = invert;
}

bool RegionEffect::doProcessing(EffectController& controller, const Layer& /*layer*/,
                                const Mesh& /*mesh*/) {
    EffectsRenderEngine& engine = controller.getEffectsRenderEngine();
    engine.getEffectDesc().getRegionConfig().configure(true, mType, mPos, mSize, mFactor, mTsize,
                                                       mInvert);
    return true;
}

void RegionEffect::postReset(EffectController& controller, const Layer& /*layer*/) {
    EffectsRenderEngine& engine = controller.getEffectsRenderEngine();
    engine.getEffectDesc().getRegionConfig().configure(false);
}

} // namespace android
