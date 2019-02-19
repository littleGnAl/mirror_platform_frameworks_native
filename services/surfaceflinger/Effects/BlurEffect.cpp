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

#include "BlurEffect.h"
#include "DisplayDevice.h"
#include "EffectController.h"
#include "EffectFBOCache.h"
#include "Layer.h"
#include "RenderEngine/EffectsRenderEngine.h"

namespace android {

BlurConfig::WeightsMap BlurConfig::sWeights;

void BlurConfig::configure(int blurRadius, const vec2& texelOffset, bool marginsEnabled,
                           const vec4& texMargins) {
    mEnabled = true;
    setRadius(blurRadius);
    mTexelOffset = texelOffset;
    mMarginsEnabled = marginsEnabled;
    mMargins = texMargins;
}

void BlurConfig::disable() {
    mEnabled = false;
    mRadius = 0;
    mTexelOffset = vec2();
    mMarginsEnabled = false;
    mMargins = vec4();
}

void BlurConfig::setRadius(int blurRadius) {
    mRadius = blurRadius;

    if (sWeights.find(blurRadius) == sWeights.end()) {
        computeWeights(blurRadius);
    }
}

void BlurConfig::setTexelOffset(const vec2& texelOffset) {
    mTexelOffset = texelOffset;
}

void BlurConfig::setMargins(const vec4& margins) {
    mMargins = margins;
}

void BlurConfig::computeWeights(int blurRadius) {
    // auto calculated sigma value
    double inputRadius = blurRadius;
    double sigma = inputRadius / sqrt(2.0 * log(255.0));

    WeightsMap::mapped_type& w = sWeights[blurRadius];

    w.resize(blurRadius + 1);
    GLfloat sumOfWeights = 0.0;
    // Calculate the sum of weight
    for (int i = 0; i < blurRadius + 1; ++i) {
        w[i] = (1.0 / sqrt(2.0 * M_PI * pow(sigma, 2.0))) *
                exp(-pow(i, 2.0) / (2.0 * pow(sigma, 2.0)));
        sumOfWeights += (i == 0) ? w[i] : 2 * w[i];
    }

    // Calculate the final weights
    for (int i = 0; i < blurRadius + 1; i++) {
        w[i] = w[i] / sumOfWeights;
    }
}

BlurEffect::BlurEffect()
      : mBlurRadius(0),
        mForceAlpha(255),
        mDownsampleFactor(1),
        mDownsampleWidth(0),
        mDownsampleHeight(0),
        mTmpMesh(Mesh::TRIANGLE_FAN, 4, 2, 2),
        mShowOld(false) {}

void BlurEffect::initFBOs(EffectController& controller, SEffectFBOCacheItem& savedItem,
                          SEffectFBOCacheItem& savedItemForHWC) {
    if (mActualBlurRadius == 0) return; // No need to allocate anything

    ALOG_ASSERT(!mFboV.isValid(), "BlurEffect: fbov must be recycled after each frame");
    ALOG_ASSERT(!mFboH.isValid(), "BlurEffect: fboh must be recycled after each frame");
    ALOG_ASSERT(!mFboU.isValid(), "BlurEffect: fbou must be recycled after each frame");

    SUPPRESS_UNUSED(savedItemForHWC);

    if (savedItem.isValid()) {
        mFboReused = savedItem;
    } else {
        mFboV = controller.getFboCache().get(mDownsampleWidth, mDownsampleHeight);
        mFboH = controller.getFboCache().get(mDownsampleWidth, mDownsampleHeight);
        mFboU = controller.getFboCache().get(mUpscaleBufferWidth, mUpscaleBufferHeight);
    }
}

void BlurEffect::clearFBOs(EffectController& controller) {
    if (mFboV.isValid()) {
        mFboV.recycle(controller.getFboCache());
    }

    if (mFboH.isValid()) {
        mFboH.recycle(controller.getFboCache());
    }

    if (mFboU.isValid()) {
        mFboU.recycle(controller.getFboCache());
    }

    if (mFboReused.isValid()) {
        mFboReused.recycle(controller.getFboCache());
    }
}

SEffectFBOCacheItem BlurEffect::saveFBO() {
    if (mFboReused.isValid()) {
        return mFboReused.transfer();
    } else if (mFboU.isValid()) {
        return mFboU.transfer();
    }
    return SEffectFBOCacheItem();
}

SEffectFBOCacheItem BlurEffect::saveFBOForHWC() {
    return SEffectFBOCacheItem();
}

int BlurEffect::getRequiredFboDownscaleFactor(EffectController& controller,
                                              const Layer& layer) const {
    SUPPRESS_UNUSED(controller);
    SUPPRESS_UNUSED(layer);
    return 1;
}

int BlurEffect::calcBlendingAlpha(const DisplayDevice& /*hw*/, const Layer& layer) const {
    // Low alpha values lead to small blur amount, do blending instead
    const Layer::State& s(layer.getDrawingState());
    int alpha = static_cast<int>((float)mBlurRadius / BLUR_BLEND_TRICK * 255.0f);
    ALOGD_IF(DEBUG, "BlurEffect::calcBlendingAlpha s.alpha=%f, alpha=%d", (double)s.color.a, alpha);
    return std::min(std::max(alpha, 0), 255);
}

bool BlurEffect::prepareCommon(EffectController& controller, const Layer& layer) {
    const DisplayDevice& hw = controller.getDisplayDevice();
    mBlurRadius = 0.0f;
    mForceAlpha = 255;

    if (mAnimator != NULL) {
        // Take the values from the animator
        if (mAnimator->hasParam(kAnimBlurRadius)) {
            mBlurRadius = mAnimator->getParam(kAnimBlurRadius);
        }
        if (mAnimator->hasParam(kAnimGenAlpha)) {
            mForceAlpha = mAnimator->getParam(kAnimGenAlpha);
        }
    } else
        mBlurRadius = DEF_RADIUS;

    if (mBlurRadius > 0) {
        float trickAlpha = calcBlendingAlpha(hw, layer);
        if (trickAlpha < 255) {
            mForceAlpha = mForceAlpha * trickAlpha / 255;
            mBlurRadius = BLUR_BLEND_TRICK;
        }
    }

    mBlurRadius = std::min(std::max(0.0f, mBlurRadius), 10000.0f);

    float blurRadius = mBlurRadius;
    // Calculate the proper downsample size & new blur radius
    mDownsampleFactor = 1;

    // Tweak for small downsample sizes
    if (mDownsampleFactor == 1 && blurRadius >= 6.6) {
        mDownsampleFactor <<= 1;
        blurRadius /= 2.2;
    }
    if (mDownsampleFactor == 2 && blurRadius >= 10) {
        mDownsampleFactor <<= 1;
        blurRadius /= 2.2;
    }
    if (mDownsampleFactor == 4 && blurRadius >= 12) {
        mDownsampleFactor <<= 1;
        blurRadius /= 2.2;
    }
    while (blurRadius >= 16) { // 8 to 16 are valid, faster but less quality with 8 (perceptible
                               // blockiness is almost none with 16)
        mDownsampleFactor <<= 1;
        blurRadius /= 2.2; // Why not 2? Because downsampling by 2 creates the visual effect of
                           // bigger blur than 2
    }

    mActualBlurRadius = static_cast<int>(blurRadius);
    mBlurAdjustCoeff = blurRadius / mActualBlurRadius;
    mShowOld = mForceAlpha < 255;
    mRenderToFBO = layer.getEffect()->getOutput() == EffectOutput::FBO;

    ALOGD_IF(DEBUG,
             "BlurEffect::prepare downsampleFactor=%d, actualBlurRadius=%d, adjustCoeff=%f, "
             "toFbo=%d",
             mDownsampleFactor, mActualBlurRadius, mBlurAdjustCoeff, (int)mRenderToFBO);

    bool updated = false;
    if (layer.isContentUpdated()) {
        updated = !mShowOld;
    }
    return updated;
}

void BlurEffect::prepare(EffectController& /*controller*/, const Layer& /*layer*/) {}

void BlurEffect::setup(EffectController& controller, const Layer& layer) {
    const DisplayDevice& hw = controller.getDisplayDevice();
    const uint32_t hw_w = hw.getWidth();
    const uint32_t hw_h = hw.getHeight();
    const Rect hwRect(hw_w, hw_h);
    Rect effectRegion = controller.getEffectRegionHW(layer);
    Rect drawRect(effectRegion);
    hwRect.intersect(drawRect, &drawRect);

    mFullscreenLayer = drawRect == hwRect;
    mTexMarginsEnabled = !mFullscreenLayer;
    ALOGD_IF(DEBUG, "BlurEffect marginsEnabled=%d", (int)mTexMarginsEnabled);

    mTexelOffset = vec2(1.0f / hw_w, 1.0f / hw_h) * mDownsampleFactor * mBlurAdjustCoeff;

    mTexMargins = vec4((float)drawRect.left / hw_w + mTexelOffset.x,
                       (float)drawRect.right / hw_w - mTexelOffset.x,
                       ((float)drawRect.top / (float)hw_h) + mTexelOffset.y,
                       ((float)drawRect.bottom / (float)hw_h) - mTexelOffset.y);

    mDisplayWidth = hw_w;
    mDisplayHeight = hw_h;
    mDownsampleWidth = hw_w / mDownsampleFactor;
    mDownsampleHeight = hw_h / mDownsampleFactor;
    mUpscaleBufferWidth = hw_w / SF_EFFECTS_BLUR_QUALITY;
    mUpscaleBufferHeight = hw_h / SF_EFFECTS_BLUR_QUALITY;
}

bool BlurEffect::doProcessing(EffectController& controller, const Layer& layer,
                              const Mesh& /*mesh*/) {
    EffectsRenderEngine& engine = controller.getEffectsRenderEngine();

    // start blurring only when the alpha value is greater than zero
    if (mForceAlpha > 0) {
        // half4 blendColor(1.0, 1.0, 1.0, mForceAlpha);
        if (mFboReused.isValid()) {
            // Set our output texture
            controller.setupFboTexture(mFboReused, true);

            engine.setupLayerBlending(layer.isPremultipliedAlpha(), false, false,
                                      (float)mForceAlpha / 255);
            return true;
        } else {
            bool ret = processBlur(controller);
            engine.setupLayerBlending(layer.isPremultipliedAlpha(), false, false,
                                      (float)mForceAlpha / 255);
            return ret;
        }
    }
    return false;
}

void BlurEffect::drawMesh(EffectsRenderEngine& engine, const SEffectFBOCacheItem& targetFbo) const {
    engine.makeRectangleMesh(targetFbo.getWidth(), targetFbo.getHeight(), mTmpMesh);
    engine.drawMesh(mTmpMesh);
}

bool BlurEffect::processBlur(EffectController& controller) {
    EffectsRenderEngine& engine = controller.getEffectsRenderEngine();

    // If we dont have to blur (just saturate, then set the shader and return)
    if (mActualBlurRadius == 0) {
        return false;
    }

    const bool isFboActive = controller.getCurrentTexture().getTextureName() != 0;
    if (isFboActive) {
        glTexParameteri(Texture::TEXTURE_2D, GL_TEXTURE_MIN_FILTER, GL_LINEAR_MIPMAP_LINEAR);
        glGenerateMipmap(Texture::TEXTURE_2D);
    }

    // disable any scissoring (we're targetting local FBOs, so the original scissor is not valid)
    engine.saveScissorAndDisable();
    engine.disableBlending(); // Overwrite all the content of the local FBO

    // Set Crop
    const Rect sourceCrop(mDownsampleWidth, mDownsampleHeight);

    ALOGD_IF(DEBUG, "BlurEffect 2. blur vertically to FBO V");
    glBindFramebuffer(GL_FRAMEBUFFER, mFboV.getName());
    engine.clearWithColor(0, 0, 0, 1); // Clean to black
    engine.setViewportAndProjection(mFboV.getWidth(), mFboV.getHeight(), sourceCrop,
                                    mFboV.getHeight(), false, Transform::ROT_0);
    engine.getEffectDesc().getBlurConfig().configure(mActualBlurRadius, vec2(mTexelOffset.x, 0.f),
                                                     mTexMarginsEnabled, mTexMargins);
    drawMesh(engine, mFboV);
    engine.getEffectDesc().getBlurConfig().disable();
    controller.setupFboTexture(mFboV, true);

    ALOGD_IF(DEBUG, "BlurEffect 3. blur horizontally and saturate to FBO H");
    glBindFramebuffer(GL_FRAMEBUFFER, mFboH.getName());
    engine.setViewportAndProjection(mFboH.getWidth(), mFboH.getHeight(), sourceCrop,
                                    mFboH.getHeight(), false, Transform::ROT_0);
    engine.getEffectDesc().getBlurConfig().configure(mActualBlurRadius, vec2(0.f, mTexelOffset.y),
                                                     mTexMarginsEnabled, mTexMargins);
    drawMesh(engine, mFboH);
    engine.getEffectDesc().getBlurConfig().disable();
    controller.setupFboTexture(mFboH, true);

    ALOGD_IF(DEBUG, "BlurEffect 4. upscale and noise");
    glBindFramebuffer(GL_FRAMEBUFFER, mFboU.getName());
    const Rect sourceCropU(mUpscaleBufferWidth, mUpscaleBufferHeight);
    engine.setViewportAndProjection(mFboU.getWidth(), mFboU.getHeight(), sourceCropU,
                                    mFboU.getHeight(), false, Transform::ROT_0);
    // adjustable parameters to reduce color banding
    const float smoothness =
            0.0001f; // enhance middle colors, both positive and negative values are allowed
    const float noise =
            1 / 256.0f; // biggest value that can be added as noise, increase to get more noise
    engine.getEffectDesc().getNoiseConfig().configure(true, smoothness, noise);
    drawMesh(engine, mFboU);
    engine.getEffectDesc().getNoiseConfig().configure(false, 0);
    controller.setupFboTexture(mFboU, true);

    engine.restoreScissor();
    return true;
}

void BlurEffect::postReset(EffectController& controller, const Layer& layer) {
    SUPPRESS_UNUSED(layer);
    EffectsRenderEngine& engine = controller.getEffectsRenderEngine();
    engine.getEffectDesc().getBlurConfig().disable();
    engine.getEffectDesc().getNoiseConfig().configure(false);
}

} // namespace android
