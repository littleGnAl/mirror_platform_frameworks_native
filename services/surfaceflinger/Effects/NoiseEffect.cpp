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

#include "NoiseEffect.h"
#include "DisplayDevice.h"
#include "EffectController.h"
#include "Layer.h"
#include "RenderEngine/EffectsRenderEngine.h"
#include "SurfaceFlinger.h"

namespace android {

void NoiseConfig::configure(bool enabled, float smoothness, float power, float seed) {
    // settters (dont need any special stuff)
    mEnabled = enabled;
    mSmoothness = smoothness;
    mPower = power;
    mSeed = seed;
}

void NoiseEffect::setup(EffectController& /*controller*/, const Layer& /*layer*/) {
    if (mAnimator != NULL) {
        // Take the values from the animator (if they are there)
        if (mAnimator->hasParam(kAnimNoiseSmoothness)) {
            mPower = mAnimator->getParam(kAnimNoiseSmoothness);
        } else {
            mPower = DEF_Smoothness;
        }
        if (mAnimator->hasParam(kAnimNoisePower)) {
            mPower = mAnimator->getParam(kAnimNoisePower);
        } else {
            mPower = DEF_Power;
        }
        if (mAnimator->hasParam(kAnimNoiseDynamic)) {
            mDynamic = mAnimator->getParam(kAnimNoiseDynamic);
        } else {
            mDynamic = DEF_Dynamic;
        }
    } else {
        mSmoothness = DEF_Smoothness;
        mPower = DEF_Power;
        mDynamic = DEF_Dynamic;
    }
}

bool NoiseEffect::doProcessing(EffectController& controller, const Layer& /*layer*/,
                               const Mesh& /*mesh*/) {
    EffectsRenderEngine& engine = controller.getEffectsRenderEngine();
    engine.getEffectDesc().getNoiseConfig().configure(true, mSmoothness, mPower,
                                                      mDynamic ? ((float)rand()) / RAND_MAX : 0);
    return true;
}

void NoiseEffect::postReset(EffectController& controller, const Layer& /*layer*/) {
    EffectsRenderEngine& engine = controller.getEffectsRenderEngine();
    engine.getEffectDesc().getNoiseConfig().configure(false);
}

} // namespace android
