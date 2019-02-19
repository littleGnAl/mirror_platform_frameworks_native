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

#ifndef ANDROID_ANIMATEDEFFECTBASE_H
#define ANDROID_ANIMATEDEFFECTBASE_H

#include <stdint.h>
#include <sys/types.h>
#include <utils/RefBase.h>

#include "Animator.h"

namespace android {

class EffectController;
class Layer;
class Mesh;

class AnimatedEffectBase : public VirtualLightRefBase {
public:
    AnimatedEffectBase();
    virtual ~AnimatedEffectBase() {}

    virtual void setAnimator(sp<Animator>& anim);
    virtual sp<Animator> getAnimator() const;
    virtual bool advanceAnimation(bool& outChanged);
    virtual bool isAnimationRunning() const;
    virtual bool isUpdated() const;
    virtual void resetUpdatedFlag();

    virtual bool prepareCommon(EffectController& /*controller*/, const Layer& /*layer*/) {
        return false;
    }
    virtual void prepare(EffectController& /*controller*/, const Layer& /*layer*/) {}
    virtual void setup(EffectController& controller, const Layer& layer) = 0;
    virtual bool doProcessing(EffectController& controller, const Layer& layer,
                              const Mesh& mesh) = 0;
    virtual void postReset(EffectController& controller, const Layer& layer) = 0;

protected:
    sp<Animator> mAnimator;
    bool mUpdated;
};

} // namespace android

#endif // ANIMATEDEFFECTBASE_H
