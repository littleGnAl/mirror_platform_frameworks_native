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

#ifndef ANDROID_REGION_H
#define ANDROID_REGION_H

#include <math/vec2.h>
#include "EffectConfig.h"
#include "EffectFBOCache.h"
#include "RegionEffect.h"

namespace android {

class Mesh;
class Layer;
class EffectController;
class EffectsRenderEngine;

class RegionConfig : public EffectConfig {
public:
    int mType;
    vec2 mPos;
    vec2 mSize;
    vec2 mFactor;
    float mTsize;
    bool mInvert;
    void configure(bool enabled = false, int type = 0, vec2 pos = vec2(), vec2 size = vec2(),
                   vec2 factor = vec2(), float tsize = 0.0f, bool inv = false);
};

class RegionEffect : public PixEffect {
public:
    virtual PixEffectType getType() const override { return PixEffectType::REGION; }

    virtual void setup(EffectController& controller, const Layer& layer) override;
    virtual bool doProcessing(EffectController& controller, const Layer& layer,
                              const Mesh& mesh) override;
    virtual void postReset(EffectController& controller, const Layer& layer) override;

private:
    // Default values
    static constexpr float DEF_X = 2560 / 2; // For ZERO, but anyway these should NOT be used
    static constexpr float DEF_Y = 1440 / 2;
    static constexpr float DEF_XSize = 0;
    static constexpr float DEF_YSize = 0;
    static constexpr float DEF_XFactor = 1;
    static constexpr float DEF_YFactor = 1;
    static constexpr bool DEF_Invert = false;
    static constexpr float DEF_TSize = 0; // Transition in percentage
    static constexpr int DEF_Type = 0;    // Circle

    vec2 mPos;
    vec2 mSize;
    vec2 mFactor;
    float mTsize{0.0f};
    bool mInvert{false};
    int mType{0};
};

}; // namespace android

#endif // ANDROID_REGION_H
