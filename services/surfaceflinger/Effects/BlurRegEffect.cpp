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

#include "BlurRegEffect.h"

#include "DisplayDevice.h"
#include "EffectController.h"
#include "Layer.h"
#include "RenderEngine/EffectsRenderEngine.h"

namespace android {

void BlurRegEffect::setup(EffectController& controller, const Layer& layer) {
    // Base Blur
    BlurEffect::setup(controller, layer);

    float posx = DEF_X;
    float posy = DEF_Y;
    float sizex = DEF_XSize;
    float sizey = DEF_YSize;
    float factorx = DEF_XFactor;
    float factory = DEF_YFactor;
    float tsize = DEF_TSize;
    int type = DEF_Type;
    bool invert = DEF_Invert;

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

bool BlurRegEffect::doProcessing(EffectController& controller, const Layer& layer,
                                 const Mesh& mesh) {
    if (!base::doProcessing(controller, layer, mesh)) {
        return false;
    }

    // Set region
    if (mForceAlpha > 0 && mSize.x > 0 && mSize.y > 0) {
        EffectsRenderEngine& engine = controller.getEffectsRenderEngine();
        engine.getEffectDesc().getRegionConfig().configure(true, mType, mPos, mSize, mFactor,
                                                           mTsize, mInvert);
    }
    return true;
}

void BlurRegEffect::postReset(EffectController& controller, const Layer& layer) {
    base::postReset(controller, layer);
    EffectsRenderEngine& engine = controller.getEffectsRenderEngine();
    engine.getEffectDesc().getRegionConfig().configure(false);
}

} // namespace android
