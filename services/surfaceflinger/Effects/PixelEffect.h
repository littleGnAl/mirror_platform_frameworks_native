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

#ifndef ANDROID_PIXEL_EFFECT_H
#define ANDROID_PIXEL_EFFECT_H

#include <stdint.h>
#include <sys/types.h>
#include <utils/RefBase.h>

#include "AnimatedEffectBase.h"
#include "Animator.h"
#include "EffectFBOCache.h"

namespace android {

class Layer;
class EffectController;

enum PixEffectType { NO_PIXEFFECT = 0, BLUR = 1, REGION_BLUR = 9, REGION = 10, NOISE = 12 };

class PixEffect : public AnimatedEffectBase {
public:
    virtual ~PixEffect() {}
    virtual PixEffectType getType() const = 0;
    virtual void initFBOs(EffectController& /*controller*/, SEffectFBOCacheItem& /*savedItem*/,
                          SEffectFBOCacheItem& /*savedItemForHWC*/) {}
    virtual void clearFBOs(EffectController& /*controller*/) {}
    virtual bool supportSaveFBO() const { return false; }
    virtual SEffectFBOCacheItem saveFBO() { return SEffectFBOCacheItem(); }
    virtual SEffectFBOCacheItem saveFBOForHWC() { return SEffectFBOCacheItem(); }
    virtual bool shouldDrawOriginalContent() const { return false; }
    virtual int getRequiredFboDownscaleFactor(EffectController& /*controller*/,
                                              const Layer& /*layer*/) const {
        return 1;
    }

    static constexpr int UNDEFINED_DOWNSCALE = -1;
};

}; // namespace android

#endif // ANDROID_PIXEL_EFFECT_H
