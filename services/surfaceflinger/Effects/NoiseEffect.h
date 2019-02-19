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

#ifndef ANDROID_NOISE_H
#define ANDROID_NOISE_H

#include "EffectConfig.h"
#include "EffectFBOCache.h"
#include "PixelEffect.h"

namespace android {

class Mesh;
class Layer;
class SurfaceFlinger;
class DisplayDevice;
class EffectController;
class EffectsRenderEngine;

class NoiseConfig : public EffectConfig {
public:
    float mSmoothness;
    float mPower;
    float mSeed;
    void configure(bool enabled, float smoothness = 0, float power = 0, float seed = 0);
};

class NoiseEffect : public PixEffect {
public:
    virtual PixEffectType getType() const override { return PixEffectType::NOISE; }

    virtual void setup(EffectController& controller, const Layer& layer) override;
    virtual bool doProcessing(EffectController& controller, const Layer& layer,
                              const Mesh& mesh) override;
    virtual void postReset(EffectController& controller, const Layer& layer) override;

private:
    // Default values
    static constexpr float DEF_Smoothness = 0.0f;
    static constexpr float DEF_Power = 1 / 256.0f;
    static constexpr bool DEF_Dynamic = false;

    float mSmoothness;
    float mPower{0.0f};
    bool mDynamic{false};
};

}; // namespace android

#endif // ANDROID_NOISE_H
