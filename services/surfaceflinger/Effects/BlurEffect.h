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

#ifndef ANDROID_BLUR_H
#define ANDROID_BLUR_H

#include <math/vec2.h>
#include <math/vec4.h>
#include <ui/Region.h>

#include "EffectConfig.h"
#include "EffectFBOCache.h"
#include "PixelEffect.h"

namespace android {

class Mesh;
class Layer;
class DisplayDevice;
class EffectController;
class EffectsRenderEngine;

// If defined the blur result will be upscaled with noise giving higher quality
#define SF_EFFECTS_BLUR_QUALITY 2 // Value is the downscaled factor for the high quality FBO

// Blur specific config for the shader (uniforms etc..)
class BlurConfig : public EffectConfig {
public:
    void configure(int blurRadius, const vec2& texelOffset, bool marginsEnabled,
                   const vec4& margins);
    void disable();
    int getRadius() const { return mRadius; }
    void setRadius(int blurRadius);
    const vec2& getTexelOffset() const { return mTexelOffset; }
    void setTexelOffset(const vec2& texelOffset);
    const vec4& getMargins() const { return mMargins; }
    void setMargins(const vec4& margins);
    bool isMarginsEnabled() const { return mMarginsEnabled; }
    const std::vector<float>& getWeights() const { return sWeights[mRadius]; }

protected:
    static void computeWeights(int blurRadius);

    // These are not safe to be changed directly, since need recompute of the weights
    int mRadius;
    vec2 mTexelOffset;
    bool mMarginsEnabled{false};
    vec4 mMargins;

    using WeightsMap = std::map<int, std::vector<float>>;
    static WeightsMap sWeights; // Map with the weights for every radius
};

class BlurEffect : public PixEffect {
public:
    BlurEffect();
    virtual PixEffectType getType() const override { return PixEffectType::BLUR; }
    virtual void initFBOs(EffectController& controller, SEffectFBOCacheItem& savedItem,
                          SEffectFBOCacheItem& savedItemForHWC) override;
    virtual void clearFBOs(EffectController& controller) override;
    virtual bool supportSaveFBO() const override { return true; }
    virtual SEffectFBOCacheItem saveFBO() override;
    virtual SEffectFBOCacheItem saveFBOForHWC() override;
    virtual bool shouldDrawOriginalContent() const override { return mShowOld; }
    virtual int getRequiredFboDownscaleFactor(EffectController& controller,
                                              const Layer& layer) const override;

    virtual bool prepareCommon(EffectController& controller, const Layer& layer) override;
    virtual void prepare(EffectController& controller, const Layer& layer) override;
    virtual void setup(EffectController& controller, const Layer& layer) override;
    virtual bool doProcessing(EffectController& controller, const Layer& layer,
                              const Mesh& mesh) override;
    virtual void postReset(EffectController& controller, const Layer& layer) override;

protected:
    void drawMesh(EffectsRenderEngine& engine, const SEffectFBOCacheItem& targetFbo) const;
    bool processBlur(EffectController& controller);

    virtual bool supportHWCComposition() const { return true; }

protected:
    int calcBlendingAlpha(const DisplayDevice& hw, const Layer& layer) const;

protected:
    static constexpr bool DEBUG = false;

    // Default values
    static constexpr float DEF_RADIUS = 352;

    // Default blur blend trick
    static constexpr float BLUR_BLEND_TRICK = 0.0f;
    static constexpr float BLUR_BLEND_COEFF = 102.0f;

    static constexpr int NUMBER_OF_FRAMES_BEFORE_HWC = 4;

    float mBlurRadius;
    int mForceAlpha;

    uint32_t mDisplayWidth;
    uint32_t mDisplayHeight;
    int mDownsampleFactor;
    uint32_t mDownsampleWidth;
    uint32_t mDownsampleHeight;
    int mActualBlurRadius{0};
    float mBlurAdjustCoeff{0};
    bool mFullscreenLayer{false};

    vec2 mTexelOffset;
    bool mTexMarginsEnabled{false};
    vec4 mTexMargins;

    // For V Blur
    SEffectFBOCacheItem mFboV;
    // For H Blur (and downsample)
    SEffectFBOCacheItem mFboH;
    SEffectFBOCacheItem mFboU;
    uint32_t mUpscaleBufferWidth;
    uint32_t mUpscaleBufferHeight;

    SEffectFBOCacheItem mFboReused;

    mutable Mesh mTmpMesh;

    bool mShowOld;
    bool mRenderToFBO{false};
};

}; // namespace android

#endif // ANDROID_BLUR_H
