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

#ifndef ANDROID_EFFECT_H
#define ANDROID_EFFECT_H

#include <stdint.h>
#include <ui/Region.h>
#include <utils/RefBase.h>

#include "Animator.h"
#include "PixelEffect.h"
#include "RenderEngine/Mesh.h"

#include <type_traits>

namespace android {

class Layer;
class BufferLayer;
class EffectController;
class Transform;

enum class EffectOutput : int {
    SCREEN, /// Saves to the screen
    FBO,    /// Saves to the EffectController FBO (for future processing)
};

enum class EffectTarget : int {
    SELF = 0x1,   /// Applies the effect to the layer itself
    BEHIND = 0x2, /// Applies the effect to all previous layers contents behind the layer (stored in
                  /// FBO)
    SELF_AND_BEHIND = SELF |
            BEHIND, /// Applies the effect to all previous layers behind and to the layer itself
};

template <typename T>
bool enumContains(T x, T y) {
    return (static_cast<typename std::underlying_type<T>::type>(x) &
            static_cast<typename std::underlying_type<T>::type>(y)) ==
            static_cast<typename std::underlying_type<T>::type>(y);
}

class EffectParams {
public:
    EffectParams() {}
    EffectParams(PixEffectType pixType, EffectOutput output, EffectTarget target)
          : pixType(pixType), output(output), target(target) {}

    EffectParams& setPixType(PixEffectType pixtype) {
        this->pixType = pixtype;
        return *this;
    }
    EffectParams& setOutput(EffectOutput output) {
        this->output = output;
        return *this;
    }
    EffectParams& setTarget(EffectTarget target) {
        this->target = target;
        return *this;
    }
    EffectParams& setRegion(const Region& region) {
        this->region = region;
        return *this;
    }
    EffectParams& setSkipLayerDrawing(bool skipLayerDrawing) {
        this->skipLayerDrawing = skipLayerDrawing;
        return *this;
    }

    PixEffectType getPixType() const { return pixType; }
    EffectOutput getOutput() const { return output; }
    EffectTarget getTarget() const { return target; }
    const Region& getRegion() const { return region; }
    bool getSkipLayerDrawing() const { return skipLayerDrawing; }

    String8 toString() const;

private:
    PixEffectType pixType{PixEffectType::NO_PIXEFFECT};
    EffectOutput output{EffectOutput::SCREEN};
    EffectTarget target{EffectTarget::SELF};
    Region region;
    bool skipLayerDrawing{false};
};

class Effect : public LightRefBase<Effect> {
public:
    virtual ~Effect() {}

    static sp<Effect> createEffect(const EffectParams& params);
    bool updateParams(const EffectParams& params);
    const EffectParams& getEffectParams() const { return mParams; }

    sp<PixEffect> getPixEffect() const { return mPixEffect; }
    PixEffectType getPixType() const {
        return mPixEffect != NULL ? mPixEffect->getType() : PixEffectType::NO_PIXEFFECT;
    }
    EffectOutput getOutput() const { return mOutput; }
    EffectTarget getTarget() const { return mTarget; }
    const Region& getRegion() const { return mRegion; }
    bool getSkipLayerDrawing() const { return mSkipLayerDrawing; }

    void setReuseFBOComposition(bool reuse) { mReuseFBOComposition = reuse; }
    bool getReuseFBOCompositionDebug() const { return mReuseFBOComposition; }

    bool advanceAnimation();
    bool isAnimationRunning() const;
    bool isUpdated() const;
    void setUpdated(bool update) { mUpdated = update; }
    void resetUpdatedFlag();

    void prepareCommon(EffectController& controller, const Layer& layer);
    void prepare(EffectController& controller, const Layer& layer);
    void draw(EffectController& controller, const Layer& layer, const Mesh& mesh,
              bool effectFboOnly = false) const;
    int getRequiredFboDownscaleFactor(EffectController& controller, const Layer& layer) const;

private:
    explicit Effect();

private:
    static sp<PixEffect> createEffect(PixEffectType type);

private:
    bool drawEffects(EffectController& controller, const Layer& layer, const Mesh& mesh) const;
    void drawLayer(EffectController& controller, const Layer& layer, const Mesh& mesh) const;
    void drawLayerToFBO(EffectController& controller, const Layer& layer, const Mesh& mesh) const;
    void drawFramebufferWithEffect(EffectController& controller, const Layer& layer) const;
    void postReset(EffectController& controller, const Layer& layer) const;
    void drawMeshWithRegion(EffectController& controller, const Layer& layer,
                            const Mesh& mesh) const;
    Mesh& prepareCompositionFBOMesh(EffectController& controller) const;
    Transform getHwOrientationTransform(EffectController& controller) const;
    Transform getCaptureTransform(EffectController& controller) const;

private:
    static constexpr bool DEBUG = false;
    static constexpr bool DEBUG_DRAW = DEBUG;

    EffectParams mParams;
    sp<PixEffect> mPixEffect;
    EffectOutput mOutput;
    EffectTarget mTarget;
    Region mRegion;
    bool mSkipLayerDrawing;

    bool mReuseFBOComposition;
    bool mUpdated;

    mutable Mesh mFboMesh;
};

}; // namespace android

#endif // ANDROID_EFFECT_H
