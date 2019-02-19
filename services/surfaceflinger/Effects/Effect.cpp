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

#include "Effect.h"
#include "BlurEffect.h"
#include "BlurRegEffect.h"
#include "BufferLayer.h"
#include "DisplayDevice.h"
#include "EffectController.h"
#include "NoneEffect.h"

namespace android {
using android::ui::Dataspace;

String8 EffectParams::toString() const {
    return String8::format("{pix=%d, out=%d, targ=%d, skdraw=%d}", (int)pixType, (int)output,
                           (int)target, (int)skipLayerDrawing);
}

Effect::Effect()
      : mOutput(EffectOutput::SCREEN),
        mTarget(EffectTarget::SELF),
        mSkipLayerDrawing(false),
        mReuseFBOComposition(false),
        mUpdated(false),
        mFboMesh(Mesh::TRIANGLE_FAN, 4, 2, 2) {}

sp<Effect> Effect::createEffect(const EffectParams& params) {
    sp<Effect> effect(new Effect());
    effect->updateParams(params);
    return effect;
}

bool Effect::updateParams(const EffectParams& params) {
    mParams = params;

    bool changed = false;
    if (mPixEffect == NULL || getPixType() != params.getPixType()) {
        mPixEffect = createEffect(params.getPixType());
        changed = true;
    }

    changed |= mOutput != params.getOutput();
    mOutput = params.getOutput();

    changed |= mTarget != params.getTarget();
    mTarget = params.getTarget();

    changed |= mRegion.getBounds() != params.getRegion().getBounds();
    mRegion = params.getRegion();

    changed |= mSkipLayerDrawing != params.getSkipLayerDrawing();
    mSkipLayerDrawing = params.getSkipLayerDrawing();

    mUpdated |= changed;

    return changed;
}

sp<PixEffect> Effect::createEffect(PixEffectType type) {
    sp<PixEffect> effect;
    switch (type) {
        case PixEffectType::BLUR:
            effect = new BlurEffect();
            break;
        case PixEffectType::REGION_BLUR:
            effect = new BlurRegEffect();
            break;
        default:
            effect = new NonePixEffect();
    }
    return effect;
}

bool Effect::advanceAnimation() {
    bool did_change = false;
    if (mPixEffect != NULL && mPixEffect->advanceAnimation(did_change)) {
        mParams.setPixType(PixEffectType::NO_PIXEFFECT);
        mPixEffect = NULL;
    }
    mUpdated |= did_change;
    return did_change;
}

bool Effect::isAnimationRunning() const {
    return mPixEffect != nullptr && mPixEffect->isAnimationRunning();
}

bool Effect::isUpdated() const {
    return mUpdated || (mPixEffect != nullptr && mPixEffect->isUpdated());
}

void Effect::resetUpdatedFlag() {
    mUpdated = false;
    if (mPixEffect != nullptr) {
        mPixEffect->resetUpdatedFlag();
    }
}

void Effect::drawLayer(EffectController& controller, const Layer& layer, const Mesh& mesh) const {
    ALOGD_IF(DEBUG_DRAW, "Effect::     # drawLayer");

    controller.bindOutput(mOutput);
    controller.setViewportAndProjection(mOutput);
    controller.drawMesh(layer, mesh);
}

void Effect::drawLayerToFBO(EffectController& controller, const Layer& layer,
                            const Mesh& mesh) const {
    ALOGD_IF(DEBUG_DRAW, "Effect::     # drawLayerToFBO");

    controller.bindOutput(EffectOutput::FBO);
    controller.setViewportAndProjection(EffectOutput::FBO);
    controller.drawMesh(layer, mesh);
}

void Effect::drawFramebufferWithEffect(EffectController& controller, const Layer& layer) const {
    EffectsRenderEngine& engine = controller.getEffectsRenderEngine();

    Mesh& mesh = prepareCompositionFBOMesh(controller);
    // Set the FBO texture
    controller.setupDefaultFboTexture(true);
    engine.setupLayerBlending(true, false, false, 1.0);
    // layer.getColor()); //This is because we dont want to overwrite what was before
    engine.setOutputDataSpace(Dataspace::SRGB);

    // TODO: calculate all aux stuff only once per frame
    const DisplayDevice& hw = controller.getDisplayDevice();
    const Rect hwRect(hw.getWidth(), hw.getHeight());
    const Rect effectRegion = controller.getEffectRegionHW(layer);
    const bool hasRegions = hwRect != effectRegion;
    const bool renderOriginalFBO =
            mPixEffect != nullptr && (mPixEffect->shouldDrawOriginalContent() || hasRegions);

    if (mOutput == EffectOutput::SCREEN && renderOriginalFBO) {
        controller.bindOutput(mOutput);
        controller.setViewportAndProjection(mOutput);
        controller.drawMesh(layer, mesh);
    }

    // Now do the processing (this will set a texture, and alpha) (use the default mesh for FBO )
    bool didproc = drawEffects(controller, layer, mesh);

    // Only render if we did some procesing
    if (didproc || mOutput == EffectOutput::SCREEN) {
        bool useExtraFBO = controller.bindOutputEx(mOutput);

        // Render to screen/FBO (apply the effect region)
        controller.setViewportAndProjection(mOutput);
        drawMeshWithRegion(controller, layer, mesh);
        // Disable any shaders the effects may have set
        postReset(controller, layer);

        if (useExtraFBO) {
            if (renderOriginalFBO) {
                // Set the FBO texture
                controller.setupExtraFboTexture(false);
                engine.setupLayerBlending(true, false, false, 1.0);
                // layer.getColor()); //This is because we dont want to overwrite what was before

                // Render to screen/FBO (apply the effect region)
                controller.bindOutput(mOutput);
                controller.setViewportAndProjection(mOutput);
                drawMeshWithRegion(controller, layer, mesh);
            } else {
                controller.swapFBOs();
            }
        }
    }
}

Mesh& Effect::prepareCompositionFBOMesh(EffectController& controller) const {
    const DisplayDevice& hw = controller.getDisplayDevice();
    EffectsRenderEngine& engine = controller.getEffectsRenderEngine();

    int32_t hw_w = hw.getWidth();
    int32_t hw_h = hw.getHeight();

    Mesh& mesh = engine.makeRectangleMesh(hw_w, hw_h, mFboMesh);

    if (controller.isCaptureEnabled() && hw.getHwRotation() != DisplayState::eOrientationDefault) {
        if ((hw.getHwRotation() & DisplayState::eOrientationSwapMask) != 0) {
            std::swap(hw_w, hw_h);
        }
        Transform tr;
        DisplayDevice::orientationToTransfrom(hw.getHwRotation(), hw_w, hw_h, &tr);
        Mesh::VertexArray<vec2> position(mesh.getPositionArray<vec2>());
        for (size_t i = 0; i < mesh.getVertexCount(); i++) {
            position[i] = tr.transform(position[i]);
        }
    }

    return mesh;
}

Transform Effect::getHwOrientationTransform(EffectController& controller) const {
    const DisplayDevice& hw = controller.getDisplayDevice();
    int32_t hw_w = hw.getWidth();
    int32_t hw_h = hw.getHeight();
    const int nHwRotation = hw.getHwRotation();
    int rotAligned = DisplayState::eOrientationDefault;

    switch (nHwRotation) {
        case DisplayState::eOrientation90:
            rotAligned = DisplayState::eOrientation270;
            hw_w = hw.getHeight();
            hw_h = hw.getWidth();
            break;
        case DisplayState::eOrientation270:
            rotAligned = DisplayState::eOrientation90;
            hw_w = hw.getHeight();
            hw_h = hw.getWidth();
            break;
        case DisplayState::eOrientation180:
            rotAligned = DisplayState::eOrientation180;
            break;
        default:
            ALOGW("Wrong HwRotation is set %d", nHwRotation);
            break;
    }

    Transform trHwOrientation;
    DisplayDevice::orientationToTransfrom(rotAligned, hw_w, hw_h, &trHwOrientation);
    return trHwOrientation;
}

void Effect::prepareCommon(EffectController& controller, const Layer& layer) {
    if (mPixEffect != nullptr) {
        mUpdated |= mPixEffect->prepareCommon(controller, layer);
    }
}

void Effect::prepare(EffectController& controller, const Layer& layer) {
    if (mPixEffect != nullptr) {
        mPixEffect->prepare(controller, layer);
    }
}

void Effect::draw(EffectController& controller, const Layer& layer, const Mesh& mesh,
                  bool effectFboOnly) const {
    controller.resetTexture();

    // Set up the effect before running it
    if (mPixEffect != NULL) {
        mPixEffect->setup(controller, layer);
    }

    // Create the FBOs the effect needs
    bool reuseEffectFbo = false;
    if (mPixEffect != NULL) {
        SEffectFBOCacheItem fboCacheItem, fboCacheItemForHWC;
        controller.takeEffectFbo(layer, fboCacheItem, fboCacheItemForHWC);
        mPixEffect->initFBOs(controller, fboCacheItem, fboCacheItemForHWC);
        if (fboCacheItem.isValid()) {
            reuseEffectFbo = true;
        }
    }

    /* Here we do the logic depending on EffectOutput and EffectTarget, in order to keep simple the
     * effect code We also take care of seting/unseting textures/FBOs This makes effectively in
     * simple to write a derived Effect, since it will be valid for any use case
     */
    const DisplayDevice& hw = controller.getDisplayDevice();

    if (mTarget == EffectTarget::SELF) {
        drawLayer(controller, layer, mesh);

    } else {
        const bool drawSelfBeforeEffect =
                !effectFboOnly && mTarget == EffectTarget::SELF_AND_BEHIND && !mSkipLayerDrawing;
        const bool drawSelfAfterEffect =
                !effectFboOnly && mTarget == EffectTarget::BEHIND && !mSkipLayerDrawing;
        if (drawSelfBeforeEffect &&
            !mReuseFBOComposition) { // If reusing Composition, then dont render it to FBO
            // Render this to FBO
            drawLayerToFBO(controller, layer, mesh);
        }

        bool restoreLayerRenderState = false;

        // First operate the FBO effect
        // If we didnt have the FBO full, and this layer is not opaque
        if (!controller.isFBOEmpty() || reuseEffectFbo) {
            drawFramebufferWithEffect(controller, layer);
            restoreLayerRenderState = true;
        }

        // Then just write this layer to the output
        if (drawSelfAfterEffect) {
            if (restoreLayerRenderState) {
                layer.setupEngineState(hw);
                controller.resetTexture();
            }
            drawLayer(controller, layer, mesh);
        }
    }

    // Tell effect controller to save the buffer if it is possible
    if (mPixEffect != NULL) {
        SEffectFBOCacheItem fbo = mPixEffect->saveFBO();
        SEffectFBOCacheItem fboForHwc = mPixEffect->saveFBOForHWC();
        if (fbo.isValid()) {
            controller.saveEffectFBO(layer, fbo, fboForHwc);
        }
    }

    // Clear any FBOs this effects have created
    if (mPixEffect != NULL) {
        mPixEffect->clearFBOs(controller);
    }

    // Revert the default output and projection for layers without effects
    controller.bindOutput(EffectOutput::SCREEN);
    controller.resetProjection();
}

void Effect::drawMeshWithRegion(EffectController& controller, const Layer& layer,
                                const Mesh& mesh) const {
    const DisplayDevice& hw = controller.getDisplayDevice();
    EffectsRenderEngine& engine = controller.getEffectsRenderEngine();

    int32_t hw_h = hw.getHeight();
    int32_t hw_w = hw.getWidth();

    Rect effectRegion = controller.getEffectRegionHW(layer);
    const bool hasRegions = effectRegion.width() != hw_w || effectRegion.height() != hw_h;

    Rect scissor = engine.saveScissorAndDisable();

    if (hasRegions) {
        if (controller.isCaptureEnabled() && mOutput == EffectOutput::SCREEN) {
            Transform trFlipv;
            trFlipv.set(Transform::FLIP_V, hw_w, hw_h);
            effectRegion = trFlipv.transform(effectRegion);

            if ((int)controller.mCaptureReqWidth > hw_w) {
                const Transform& tr = hw.getTransform();
                effectRegion = tr.inverse().transform(effectRegion);
            }

            Transform trHwOrientation = getHwOrientationTransform(controller);
            if (trHwOrientation.getType() != Transform::IDENTITY) {
                effectRegion = trHwOrientation.transform(effectRegion);
            }

            Transform trCaptureTransform;
            trCaptureTransform.set(controller.mCaptureOrientation, controller.mCaptureReqWidth,
                                   controller.mCaptureReqHeight);
            if (trCaptureTransform.getType() != Transform::IDENTITY) {
                effectRegion = trCaptureTransform.transform(effectRegion);
            }
        }

        controller.setScissor(effectRegion, mOutput);
    }

    controller.drawMesh(layer, mesh);

    if (scissor.isValid()) {
        engine.setScissor(scissor.left, scissor.top, scissor.width(), scissor.height());
    } else {
        engine.disableScissor();
    }
}

bool Effect::drawEffects(EffectController& controller, const Layer& layer, const Mesh& mesh) const {
    bool didproc = false;
    didproc |= mPixEffect != nullptr && mPixEffect->doProcessing(controller, layer, mesh);
    return didproc;
}

int Effect::getRequiredFboDownscaleFactor(EffectController& controller, const Layer& layer) const {
    if (mPixEffect != nullptr) {
        return mPixEffect->getRequiredFboDownscaleFactor(controller, layer);
    }
    return PixEffect::UNDEFINED_DOWNSCALE;
}

void Effect::postReset(EffectController& controller, const Layer& layer) const {
    if (mPixEffect != NULL) {
        mPixEffect->postReset(controller, layer);
    }
}

} // namespace android
