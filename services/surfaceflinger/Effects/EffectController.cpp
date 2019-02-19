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

#include <cutils/log.h>
#include <cutils/properties.h>

#include <GLES2/gl2.h>

#include "EffectController.h"
#include "Interpolator.h"
#include "RenderEngine/GLExtensions.h"
#include "RenderEngine/Texture.h"
#include "TransformUtils.h"

#include "BufferLayer.h"
#include "RenderEngine/EffectsRenderEngine.h"
#include "RenderEngine/RenderEngine.h"

#include "DisplayDevice.h"
#include "RenderArea.h"

#include "Animator.h"
#include "Effect.h"
#include "EffectFBOCache.h"

#include <algorithm>

namespace android {

EffectController::EffectController(const SurfaceFlinger& flinger, const DisplayDevice& hw)
      : mEngine(static_cast<EffectsRenderEngine&>(flinger.getRenderEngine())),
        mHW(hw),
        mRenderArea(NULL),
        mFBOCache(static_cast<EffectsRenderEngine&>(flinger.getRenderEngine())),
        mFBOIsEmpty(true),
        mFlinger(flinger),
        mCaptureFbName(0),
        mCaptureTexFbName(0),
        mCaptureReqWidth(0),
        mCaptureReqHeight(0),
        mCaptureOrientation(Transform::ROT_0) {}

EffectController::~EffectController() {
    clearFBOs();
}

void EffectController::initFBOs(int downScaleFactor, bool keepBiggerFbo, bool extraFbo) {
    const uint32_t hw_w = mHW.getWidth();
    const uint32_t hw_h = mHW.getHeight();
    const uint32_t fboWidth = hw_w / downScaleFactor;
    const uint32_t fboHeight = hw_h / downScaleFactor;

    mFboDownscaleFactor = downScaleFactor;

    if (!mFbo.isValid() || (mFbo.getWidth() < fboWidth) ||
        (mFbo.getWidth() > fboWidth && !keepBiggerFbo)) {
        if (mFbo.isValid()) {
            mFBOCache.recycle(mFbo);
        }
        mFbo = mFBOCache.get(fboWidth, fboHeight);
    }
    if (extraFbo) {
        if (!mFboEx.isValid() || (mFboEx.getWidth() < fboWidth) ||
            (mFboEx.getWidth() > fboWidth && !keepBiggerFbo)) {
            if (mFboEx.isValid()) {
                mFBOCache.recycle(mFboEx);
            }
            mFboEx = mFBOCache.get(fboWidth, fboHeight);
        }
    }
}

void EffectController::clearFBOs() {
    if (mFbo.isValid()) {
        mFbo.recycle(mFBOCache);
    }
    if (mFboEx.isValid()) {
        mFboEx.recycle(mFBOCache);
    }
    // Clear the saved FBOs from effects reuse
    for (const auto& item : mSaveFBO) {
        mFBOCache.recycle(item.second.fbo);
        mFBOCache.recycle(item.second.fboForHWC);
    }
    mSaveFBO.clear();
    mFBOCache.clear(); // Clear our child effects FBOs
}

void EffectController::saveEffectFBO(const Layer& layer, const SEffectFBOCacheItem& item,
                                     const SEffectFBOCacheItem& itemForHWC) {
    ALOGE_IF(DEBUG_REUSE, "EC::saveEffectFBO layer=%s, name=%d", layer.getName().string(),
             item.getName());

    // Check if the FBO already has a saved value for this layer
    auto it = mSaveFBO.find(&layer);
    if (it != mSaveFBO.end()) {
        mFBOCache.recycle(it->second.fbo);
        mFBOCache.recycle(it->second.fboForHWC);
        mSaveFBO.erase(it);
    }
    if (item.isValid()) {
        mSaveFBO[&layer] = FboCacheEntry{item, itemForHWC};
    }
}

void EffectController::takeEffectFbo(const Layer& layer, SEffectFBOCacheItem& item,
                                     SEffectFBOCacheItem& itemForHWC) {
    auto it = mSaveFBO.find(&layer);
    if (it == mSaveFBO.end()) {
        return;
    }
    item.swap(it->second.fbo);
    itemForHWC.swap(it->second.fboForHWC);
    mSaveFBO.erase(it);

    ALOGE_IF(DEBUG_REUSE, "EC::takeEffectFbo layer=%s, name=%d", layer.getName().string(),
             item.getName());
}

bool EffectController::setEffectConsistency(const Vector<sp<Layer>>& layersSortedByZ) const {
    bool changed = false;
    bool firstBehindEffectFound = false;
    bool effectFound = false;
    for (int i = layersSortedByZ.size() - 1; i >= 0; i--) {
        const sp<Layer>& layer(layersSortedByZ[i]);
        if (layer->hasEffect()) {
            sp<Effect> ef = layer->getEffect();
            effectFound = true;

            if (ef->getPixType() == PixEffectType::NO_PIXEFFECT) {
                // If this is a placeholder effect
                if (firstBehindEffectFound) {
                    if (ef->getOutput() != EffectOutput::FBO) {
                        EffectParams params(ef->getEffectParams());
                        params.setOutput(EffectOutput::FBO).setTarget(EffectTarget::SELF);
                        ef->updateParams(params);
                        changed = true;
                    }
                } else {
                    layer->removeEffect(); // Non sense to have an effect that does nothing and
                                           // outputs to screen/FBO
                    changed = true;
                    continue;
                }

            } else if (!firstBehindEffectFound && ef->getOutput() == EffectOutput::FBO) {
                // If a behind effect hasn't been found yet, this effect cannot output to FBO,
                // fixing it here
                EffectParams params(ef->getEffectParams());
                params.setOutput(EffectOutput::SCREEN);
                layer->setEffect(params);
                changed = true;

            } else if (firstBehindEffectFound && ef->getOutput() != EffectOutput::FBO) {
                // If a behind effect has been found, this effect has to output to FBO, fixing it
                // here
                EffectParams params(ef->getEffectParams());
                params.setOutput(EffectOutput::FBO);
                layersSortedByZ[i]->setEffect(params);
                changed = true;
            }

            // This's a behing effect
            if (enumContains(ef->getTarget(), EffectTarget::BEHIND)) {
                firstBehindEffectFound = true;
            }
        } else if (firstBehindEffectFound) {
            // No effect but in Prev mode, create empty placeholder effects to output to FBO
            EffectParams params{PixEffectType::NO_PIXEFFECT, EffectOutput::FBO, EffectTarget::SELF};
            layer->setEffect(params);
            changed = true;
        }
    }

    if (DEBUG_CONSISTENCY && effectFound) {
        ALOGE("EC::setEffectConsistency @@ num layers %d", (int)layersSortedByZ.size());
        for (const sp<Layer>& layer : layersSortedByZ) {
            if (layer->hasEffect()) {
                sp<Effect> effect = layer->getEffect();
                ALOGE("EC:: @@     layer=%s, effect=YES, pix=%d, out=%d, target=%d",
                      layer->getName().string(), (int)effect->getPixType(),
                      (int)effect->getOutput(), (int)effect->getTarget());
            } else {
                ALOGE("EC:: @@     layer=%s, effect: NO", layer->getName().string());
            }
        }
    }
    ALOGE_IF(DEBUG_CONSISTENCY, "EC::setEffectConsistency changed=%d", (int)changed);
    return changed;
}

bool EffectController::prepareCommon(const Vector<sp<Layer>>& layersSortedByZ) {
    // TODO for the time being we are hardcoding the effects, but each layer may have a different
    // effect We should analyze the flags of every layer and set up appropiately the effects in the
    // surfaceflinger, not here

    // Check consistency, will modify slightly the effects in order to avoid any miss-configuration
    // (kFBO/kScreen and kPrev)
    // Will also destroy effects that are not doing anything.

    bool validateHWCRequired = setEffectConsistency(layersSortedByZ);

    for (const sp<Layer>& layer : layersSortedByZ) {
        if (layer->hasEffect()) {
            sp<Effect> effect = layer->getEffect();
            effect->prepareCommon(*this, *layer);
        }
    }

    return validateHWCRequired;
}

bool EffectController::checkReuseFBOs(const Vector<sp<Layer>>& layersSortedByZ,
                                      bool biggerFboIsRequired) {
    /// The logic here is that we need to choose whitch layers are not rendered, and witch effects
    /// reused
    ///  We start with all the output of previous effects and the list of not-render clear
    ///  First we check if we have any prev effect, and we take the last one.
    ///    That is the composition buffer status. If the composition buffer constrains are met, all
    ///    the data can be reused. There is even no need to redraw the intermediate effects output.
    ///    In that case, we mark the previous layers not to render, In case it fails, we relay on
    ///    individual effects FBO reuse
    ///  Then, we check each Saved data, and check that no change in layers/Update/Animation/Manual
    ///  change
    ///    has been done. In order to keep the FBO as valid.
    ///    In the case it is a Prev + No show Old case, we can mark the previous layers as not
    ///    render as well. Otherwise we remove the Saved buffer.
    ///  Another extra thing we do here is to save current "saveable" effects dependancys,
    ///    to certify next frame that the dependancy is correct or not, we do it at the same time we
    ///    check the dependancy
    ///  TODO: Last thing, is to check how can we tweak the normal layer stacks, so that the HWC can
    ///  take take of FBO renders
    ///    avoiding GPU usage at all (highly unstable and WIP:Work In Progress)

    ALOGE_IF(DEBUG_REUSE, "EC::checkReuseEffects >>>>");
    NotInRenderMap notInRenderPrev(mNotRender);
    mNotRender.clear(); // We are going to rebuild it

    Vector<sp<Layer>> effectLayersSortedByZ;
    effectLayersSortedByZ.reserve(layersSortedByZ.size());
    std::copy_if(layersSortedByZ.begin(), layersSortedByZ.end(),
                 std::back_inserter(effectLayersSortedByZ),
                 [](const sp<Layer>& l) { return l->hasEffect(); });

    checkReuseCompositionFBOs(effectLayersSortedByZ, biggerFboIsRequired);
    checkReuseSavedFBOs(effectLayersSortedByZ);

    bool invalidateHWCRequired = mNotRender != notInRenderPrev;

    ALOGE_IF(DEBUG_REUSE, "EC::checkReuseEffects invalidateHWCRequired=%d<<<<",
             (int)invalidateHWCRequired);
    return invalidateHWCRequired;
}

void EffectController::checkReuseCompositionFBOs(const Vector<sp<Layer>>& effectLayersSortedByZ,
                                                 bool biggerFboIsRequired) {
    // Clean the reuse composition flags for all layers with effects
    for (const sp<Layer> layer : effectLayersSortedByZ) {
        const sp<Effect> effect = layer->getEffect();
        effect->setReuseFBOComposition(false);
    }

    // Search for the last prev effect
    int lastBehindEffectIndex = -1;
    for (int i = effectLayersSortedByZ.size() - 1; i >= 0; i--) {
        const sp<Layer>& l = effectLayersSortedByZ[i];
        if (enumContains(l->getEffect()->getTarget(), EffectTarget::BEHIND)) {
            lastBehindEffectIndex = i;
            break;
        }
    }

    CompositionDependencyList newCompositionDependencies;
    if (lastBehindEffectIndex != -1) {
        // Check the composition FBO validity
        const sp<Layer>& lastBehindEffectLayer = effectLayersSortedByZ[lastBehindEffectIndex];
        const sp<Effect>& lastBehindEffect = lastBehindEffectLayer->getEffect();
        const EffectTarget lastBehindEffectTarget = lastBehindEffect->getTarget();

        if (lastBehindEffectTarget == EffectTarget::SELF_AND_BEHIND) {
            newCompositionDependencies.push_back(lastBehindEffectLayer.get());
        }

        for (int i = 0; i < lastBehindEffectIndex; i++) {
            newCompositionDependencies.push_back(effectLayersSortedByZ[i].get());
        }

        if (DEBUG_REUSE) {
            ALOGE("EC::checkReuseEffects @ lastBehindEffectLayer=%s",
                  lastBehindEffectLayer->getName().string());
            for (const auto& depLayer : newCompositionDependencies) {
                ALOGE("EC::checkReuseEffects @     depLayer=%s", depLayer->getName().string());
            }
        }

        // Have the layers changed?
        const bool depsAreTheSame = mCompositionDependencies == newCompositionDependencies;
        if (DEBUG_REUSE) {
            ALOGE_IF(!depsAreTheSame, "EC::checkReuseEffects @     dependencies changed");
            ALOGE_IF(biggerFboIsRequired, "EC::checkReuseEffects @     biggerFboIsRequired");
        }
        const bool fboCompositionValid = !biggerFboIsRequired && depsAreTheSame &&
                std::all_of(mCompositionDependencies.begin(), mCompositionDependencies.end(),
                            [&lastBehindEffectLayer](const Layer* depLayer) {
                                if (depLayer->isContentUpdated()) {
                                    ALOGE_IF(DEBUG_REUSE,
                                             "EC::checkReuseEffects @     content updated %s",
                                             depLayer->getName().string());
                                    return false;
                                }

                                // We dont care if the effect updated in the ThisPrev Layer
                                if (depLayer != lastBehindEffectLayer.get() &&
                                    depLayer->getEffect()->isUpdated()) {
                                    ALOGE_IF(DEBUG_REUSE,
                                             "EC::checkReuseEffects @     effect updated %s",
                                             depLayer->getName().string());
                                    return false;
                                }
                                return true;
                            });

        ALOGE_IF(DEBUG_REUSE, "EC::checkReuseEffects @     fboCompositionValid=%d",
                 (int)fboCompositionValid);

        // Set the Composition depend to the new value
        if (fboCompositionValid) {
            // We can mark all the layers as not render (including those with effects, except the
            // "Prev" itself)
            for (const Layer* layer : newCompositionDependencies) {
                if (layer != lastBehindEffectLayer.get()) {
                    mNotRender[layer] = lastBehindEffectLayer.get();
                }
            }
            if (lastBehindEffect->getPixEffect() != NULL) {
                lastBehindEffect->setReuseFBOComposition(true);
                mFBOIsEmpty = false;
            }
        }
    }
    mCompositionDependencies.swap(newCompositionDependencies);
}

void EffectController::checkReuseSavedFBOs(const Vector<sp<Layer>>& effectLayersSortedByZ) {
    // Discard the saved data of effects whose dependancy has changed, and save the new dependancy
    ReuseDependencyMap newReuseDependencies;
    for (auto it = effectLayersSortedByZ.begin(); it != effectLayersSortedByZ.end(); ++it) {
        const sp<Layer>& layer = *it;
        const sp<Effect>& effect = layer->getEffect();
        const EffectTarget target = effect->getTarget();
        if (effect->getPixEffect() == NULL) {
            continue;
        }
        if (!effect->getPixEffect()->supportSaveFBO()) {
            continue;
        }

        CompositionDependencyList layerDependencies;
        if (enumContains(target, EffectTarget::SELF)) {
            layerDependencies.push_back(layer.get());
        }
        if (enumContains(target, EffectTarget::BEHIND)) {
            for (auto it2 = effectLayersSortedByZ.begin(); it2 != it; ++it2) {
                layerDependencies.push_back(it2->get());
            }
        }

        // Save it, since is valid
        newReuseDependencies[layer.get()] = layerDependencies;
    }

    // Now process the mSaveFBO
    ReuseDependencyMap& oldReuseDependencies = mReuseDependencies;
    for (auto it = mSaveFBO.begin(); it != mSaveFBO.end();) {
        auto currentIt = it++;
        const Layer* layer = currentIt->first;

        ALOGE_IF(DEBUG_REUSE, "EC::checkReuseEffects @@ saved fbo for %s",
                 layer->getName().string());

        auto isValid = [&oldReuseDependencies, &newReuseDependencies](const Layer* layer) {
            // Check if the layer still exists, and did pass the dependancy test avobe
            const auto layerDepenenciesIt = newReuseDependencies.find(layer);
            if (layerDepenenciesIt == newReuseDependencies.end()) {
                ALOGE_IF(DEBUG_REUSE, "EC::checkReuseEffects @@     layer was removed");
                return false;
            }

            if (!layer->hasEffect()) {
                ALOGE_IF(DEBUG_REUSE, "EC::checkReuseEffects @@     no effect");
                return false;
            }

            const sp<Effect>& effect = layer->getEffect();

            CompositionDependencyList layerDependencies = layerDepenenciesIt->second;

            if (DEBUG_REUSE) {
                for (const auto& depLayer : layerDependencies) {
                    ALOGE("EC::checkReuseEffects @@     depLayer=%s", depLayer->getName().string());
                }
            }

            // Check that effect did not update since last run
            if (effect->isUpdated()) {
                ALOGE_IF(DEBUG_REUSE, "EC::checkReuseEffects @@     effect updated");
                return false;
            }

            // Have the layers changed?
            if (oldReuseDependencies[layer] != layerDependencies) {
                ALOGE_IF(DEBUG_REUSE, "EC::checkReuseEffects @@     dependencies changed");
                return false;
            }

            // Have the layers changed?
            return std::all_of(layerDependencies.begin(), layerDependencies.end(),
                               [](const Layer* depLayer) {
                                   if (depLayer->isContentUpdated()) {
                                       ALOGE_IF(DEBUG_REUSE,
                                                "EC::checkReuseEffects @@     content updated %s",
                                                depLayer->getName().string());
                                       return false;
                                   }
                                   // Did the effect update in those layers?
                                   if (depLayer->getEffect()->isUpdated()) {
                                       ALOGE_IF(DEBUG_REUSE,
                                                "EC::checkReuseEffects @@     effect updated %s",
                                                depLayer->getName().string());
                                       return false;
                                   }
                                   return true;
                               });
        };

        const bool isFboValid = isValid(layer);
        ALOGE_IF(DEBUG_REUSE, "EC::checkReuseEffects @@     isFboValid=%d", (int)isFboValid);
        if (isFboValid) {
            const sp<Effect>& effect = layer->getEffect();
            // If it's valid, is Prev, and showold is false, we can mark whatever is behind as
            // mNotRender
            if (enumContains(effect->getTarget(), EffectTarget::BEHIND)) {
                effect->setReuseFBOComposition(true);
                mFBOIsEmpty = false;
                for (const Layer* layerToCheck : mReuseDependencies[layer]) {
                    if (layerToCheck != layer) {
                        mNotRender[layerToCheck] = layer;
                    }
                };
            }
        } else {
            mFBOCache.recycle(currentIt->second.fbo);
            mFBOCache.recycle(currentIt->second.fboForHWC);
            mSaveFBO.erase(currentIt);
        }
    }
    mReuseDependencies.swap(newReuseDependencies);
}

sp<GraphicBuffer> EffectController::getBufferForHWC(const Layer& layer) const {
    auto it = mSaveFBO.find(&layer);
    if (it != mSaveFBO.end()) {
        const SEffectFBOCacheItem& savedFbo = it->second.fboForHWC;
        sp<GraphicBuffer> buffer = savedFbo.getBuffer();
        const uint32_t hw_w = mHW.getWidth();
        const uint32_t hw_h = mHW.getHeight();

        if (buffer != nullptr && buffer->getWidth() >= hw_w / SF_EFFECTS_HWC_MAX_DOWNSCALE &&
            buffer->getHeight() >= hw_h / SF_EFFECTS_HWC_MAX_DOWNSCALE) {
            return buffer;
        }
    }
    return nullptr;
}

bool EffectController::notInRender(const sp<Layer>& layer) const {
    return mNotRender.find(layer.get()) != mNotRender.end();
}

bool EffectController::shouldBeRenderedTwice(const sp<Layer>& /*layer*/) const {
    return false;
}

bool EffectController::needExtraFBO(const Vector<sp<Layer>>& layersSortedByZ) const {
    // Check if any effect is active, to create/destroy the FBO
    auto it = std::find_if(layersSortedByZ.begin(), layersSortedByZ.end(),
                           [](const sp<Layer>& layer) {
                               return layer->hasEffect() &&
                                       enumContains(layer->getEffect()->getTarget(),
                                                    EffectTarget::BEHIND) &&
                                       layer->getEffect()->getOutput() == EffectOutput::FBO;
                           });

    if (DEBUG && it != layersSortedByZ.end()) {
        ALOGE("EC::needExtraFBO FBO needed for layer %s", (*it)->getName().string());
    }
    return it != layersSortedByZ.end();
}

bool EffectController::prepare(const Vector<sp<Layer>>& layersSortedByZ) {
    // Check if any effect is active, to create/destroy the FBO
    int downScaleFactor = PixEffect::UNDEFINED_DOWNSCALE;
    bool useFbo = false;
    for (const sp<Layer>& layer : layersSortedByZ) {
        if (layer->hasEffect()) {
            sp<Effect> effect = layer->getEffect();
            effect->prepare(*this, *layer);

            useFbo = true;
            int requiredDownscaleFactor = effect->getRequiredFboDownscaleFactor(*this, *layer);
            if (requiredDownscaleFactor != PixEffect::UNDEFINED_DOWNSCALE) {
                downScaleFactor = requiredDownscaleFactor;
            }
        }
    }
    downScaleFactor = std::max(1, std::min(downScaleFactor, 4));
    const bool biggerFboIsRequired = downScaleFactor < mFboDownscaleFactor;

    // calculate effect regions
    const size_t count = layersSortedByZ.size();
    Region outputRegion;
    for (size_t i = 0; i < count; i++) {
        const sp<Layer>& layer = layersSortedByZ[i];
        const Region& layerRegion = layer->visibleRegion;
        if (layer->hasEffect()) {
            Rect outEffectRegion = layerRegion.getBounds();
            Rect oldOutEffectRegion = mEffectRegionsMap[layer.get()];
            Rect effectRegion = layer->getEffect()->getRegion().getBounds();
            if (effectRegion.getWidth() >= 10000 || effectRegion.getHeight() >= 10000) {
                outEffectRegion = outputRegion.getBounds();
            } else if (!effectRegion.isEmpty()) {
                Transform scale(layer->getDrawingState().active.transform);
                scale.set(0, 0);
                effectRegion = scale.transform(effectRegion);
                const Rect& layerBounds = layerRegion.getBounds();
                effectRegion.offsetBy(layerBounds.left, layerBounds.top);
                layerBounds.intersect(effectRegion, &outEffectRegion);
            }
            const Rect& viewport = mHW.getViewport();
            viewport.intersect(outEffectRegion, &outEffectRegion);
            const Transform& tr = mHW.getTransform();

            const uint32_t hw_h = mHW.getHeight();
            outEffectRegion = tr.transform(outEffectRegion);
            outEffectRegion = Rect(outEffectRegion.left, hw_h - outEffectRegion.bottom,
                                   outEffectRegion.right, hw_h - outEffectRegion.top);
            mEffectRegionsMap[layer.get()] = outEffectRegion;

            if (oldOutEffectRegion != outEffectRegion) layer->getEffect()->setUpdated(true);
        }
        outputRegion.orSelf(layerRegion);
    }

    // Mark the FBO contains obsolete data
    mFBOIsEmpty = true;
    bool invalidateHWCRequired = checkReuseFBOs(layersSortedByZ, biggerFboIsRequired);

    if (useFbo) {
        const bool extraFBO = needExtraFBO(layersSortedByZ);
        initFBOs(downScaleFactor, !mFBOIsEmpty, extraFBO);
    } else {
        clearFBOs();
    }
    bindDefaultOutput();

    return invalidateHWCRequired;
}

void EffectController::prepareCompleted(const Vector<sp<Layer>>& layersSortedByZ) const {
    // mark all layers as clean, no content update, no effect update!
    for (size_t i = 0; i < layersSortedByZ.size(); i++) {
        if (layersSortedByZ[i]->hasEffect()) {
            layersSortedByZ[i]->setContentUpdated(false);
            layersSortedByZ[i]->getEffect()->resetUpdatedFlag();
        }
    }
}

void EffectController::composeLayer(const Layer& layer, const Mesh& mesh, int index) {
    // If it has an effect run it, otherwise do the default operation
    if (layer.hasEffect() && !layer.skipEffect) {
        sp<Effect> ef = layer.getEffect();

        SUPPRESS_UNUSED(index);
        ef->draw(*this, layer, mesh);
    } else {
        mEngine.drawMesh(mesh);
    }
}

void EffectController::setContentUpdatedForScreenshot() {
    const Vector<sp<Layer>>& layersSortedByZ = mHW.getVisibleLayersSortedByZ();
    for (size_t i = 0; i < layersSortedByZ.size(); i++) {
        layersSortedByZ[i]->setContentUpdated(true);
    }
}

bool EffectController::setPerFrameData(Layer& layer, int index) {
    SUPPRESS_UNUSED(index);
    if (layer.hasEffect()) {
        auto hwcId = mHW.getHwcDisplayId();
        layer.setCompositionType(hwcId, HWC2::Composition::Client);
    }
    return false;
}

void EffectController::setCaptureParams(uint32_t width, uint32_t height, const Rect& sourceRect,
                                        uint32_t raHeight,
                                        Transform::orientation_flags orientation) {
    mCaptureReqWidth = width;
    mCaptureReqHeight = height;
    mCaptureSourceRect = sourceRect;
    mCaptureReqRaHeight = raHeight;
    mCaptureOrientation = orientation;
}

void EffectController::enableCapture(uint32_t fbName, uint32_t fbTexName) {
    mCaptureFbName = fbName;
    mCaptureTexFbName = fbTexName;
}

void EffectController::disableCapture() {
    mCaptureFbName = 0;
    mCaptureTexFbName = 0;

    mCaptureReqWidth = 0;
    mCaptureReqHeight = 0;
    mCaptureSourceRect.clear();
    mCaptureOrientation = Transform::ROT_0;
}

Rect EffectController::getEffectRegionHW(const Layer& layer) const {
    Rect res = layer.visibleRegion.getBounds();
    auto it = mEffectRegionsMap.find(&layer);
    if (it != mEffectRegionsMap.end()) {
        res = it->second;
    }
    return res;
}

void EffectController::setViewportAndProjection(EffectOutput output) const {
    int32_t hw_w = mHW.getWidth();
    int32_t hw_h = mHW.getHeight();

    int viewportWidth = output == EffectOutput::FBO ? mFbo.getWidth() : hw_w;
    int viewportHeight = output == EffectOutput::FBO ? mFbo.getHeight() : hw_h;

    int source_w = hw_w;
    int source_h = hw_h;
    if (isCaptureEnabled() && (mHW.getHwRotation() & DisplayState::eOrientationSwapMask) != 0) {
        std::swap(source_w, source_h);
    }
    Rect sourceCrop = Rect(source_w, source_h);

    bool yswap = false;
    Transform::orientation_flags rotation = Transform::ROT_0;

    if (output == EffectOutput::SCREEN && isCaptureEnabled()) {
        viewportWidth = mCaptureReqWidth;
        viewportHeight = mCaptureReqHeight;
        sourceCrop = mCaptureSourceRect;
        source_h = mCaptureReqRaHeight;
        yswap = true;
        rotation = mCaptureOrientation;
    } else if (isCaptureEnabled() && mHW.getHwRotation() != DisplayState::eOrientationDefault) {
        rotation = TransformUtils::hwRotationToTransformFlagsInv(mHW.getHwRotation());
    }

    mEngine.setViewportAndProjection(viewportWidth, viewportHeight, sourceCrop, source_h, yswap,
                                     rotation);
}

void EffectController::setScissor(const Rect& rect, EffectOutput output) const {
    SUPPRESS_UNUSED(output);
    mEngine.setScissor(rect.left, rect.top, rect.getWidth(), rect.getHeight());
}

void EffectController::resetProjection() const {
    setViewportAndProjection(EffectOutput::SCREEN);
}

void EffectController::bindFboOutput() {
    glBindFramebuffer(GL_FRAMEBUFFER, mFbo.getName());
}

void EffectController::bindDefaultOutput() {
    // Default output is the capture FBO
    if (isCaptureEnabled()) {
        glBindFramebuffer(GL_FRAMEBUFFER, mCaptureFbName);
    } else {
        //#ifdef  USE_MULTI_DOWNSCALE
        //        if( mHW.getDisplayType() == DisplayDevice::DISPLAY_VIRTUAL &&
        //        mHW.isMultiDownscaleMode() == true ) {
        //            ALOGE_IF(DEBUG, "EC:: Virtual and Multi downscale mode, Draw into
        //            MDS_FboName"); glBindFramebuffer(GL_FRAMEBUFFER, mHW.mMDS_FboName);
        //        }else
        //#endif
        glBindFramebuffer(GL_FRAMEBUFFER, mEngine.getGroupStackFbo());
    }
}

void EffectController::bindOutput(EffectOutput output) {
    if (output == EffectOutput::FBO) {
        bindFboOutput();
        // The first time the FBO is used by an effect we should clear it
        if (mFBOIsEmpty) {
            clearFBOOutput();
            mFBOIsEmpty = false;
        }
    } else {
        bindDefaultOutput();
    }
}

bool EffectController::bindOutputEx(EffectOutput output) {
    // If the effects did not change the texture, and the output is again to FBO we have a recursion
    // problem To solve it, use the extra FBO in Effect controller
    const bool useExtraFBO = (output == EffectOutput::FBO) &&
            (getCurrentTexture().getTextureName() == mFbo.getTexName());
    if (useExtraFBO) {
        glBindFramebuffer(GL_FRAMEBUFFER, mFboEx.getName());
        // Clear it (with alpha, since we will blend again to FBO)
        mEngine.saveScissorAndDisable();
        mEngine.clearWithColor(0, 0, 0, 0);
        mEngine.restoreScissor();
        ALOGE_IF(DEBUG, "EC::bindOutputEx FBO TO FBO[2]");
    } else {
        bindOutput(output);
    }
    return useExtraFBO;
}

void EffectController::swapFBOs() {
    mFbo.swap(mFboEx);
}

void EffectController::clearFBOOutput() {
    mEngine.saveScissorAndDisable();
    mEngine.clearWithColor(0, 0, 0, 1); // Clear to black
    mEngine.restoreScissor();
}

void EffectController::resetTexture() {
    mCurrentFboTexture.init(Texture::TEXTURE_2D, 0);
}

void EffectController::setupTexture(const Texture& texture) {
    mCurrentFboTexture.init((Texture::Target)texture.getTextureTarget(), texture.getTextureName());
    mCurrentFboTexture.setDimensions(texture.getWidth(), texture.getHeight());
    mCurrentFboTexture.setFiltering(texture.getFiltering());
    mEngine.setupLayerTexturing(texture);
}

void EffectController::setupFboTexture(const SEffectFBOCacheItem& fbo, bool filtering) {
    Texture& texture = mCurrentFboTexture;
    texture.init(Texture::TEXTURE_2D, fbo.getTexName());
    texture.setDimensions(fbo.getWidth(), fbo.getHeight());
    texture.setFiltering(filtering);
    mEngine.setupLayerTexturing(texture);
}

void EffectController::setupDefaultFboTexture(bool filtering) {
    setupFboTexture(mFbo, filtering);
}

void EffectController::setupExtraFboTexture(bool filtering) {
    setupFboTexture(mFboEx, filtering);
}

void EffectController::drawMesh(const Layer& /*layer*/, const Mesh& mesh) {
    mEngine.drawMesh(mesh);
}

bool EffectController::getDisableHWC() const {
    return mFlinger.mDebugDisableHWC;
}

} // namespace android
