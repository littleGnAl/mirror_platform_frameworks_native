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

#ifndef ANDROID_NONEEFFECT_H
#define ANDROID_NONEEFFECT_H

#include "PixelEffect.h"
#include "RenderEngine/EffectsRenderEngine.h"

namespace android {

class Mesh;
class Layer;

class NonePixEffect : public PixEffect {
public:
    virtual PixEffectType getType() const override { return PixEffectType::NO_PIXEFFECT; }

    virtual void setup(EffectController& /*controller*/, const Layer& /*layer*/) override {}
    virtual bool doProcessing(EffectController& /*controller*/, const Layer& /*layer*/,
                              const Mesh& /*mesh*/) override {
        return false;
    }
    virtual void postReset(EffectController& /*controller*/, const Layer& /*layer*/) override {}
    virtual int getRequiredFboDownscaleFactor(EffectController& /*controller*/,
                                              const Layer& /*layer*/) const {
        return UNDEFINED_DOWNSCALE;
    }
};
}; // namespace android

#endif // ANDROID_NONEEFFECT_H
