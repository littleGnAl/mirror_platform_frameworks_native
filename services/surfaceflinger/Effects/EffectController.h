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

#ifndef ANDROID_SURFACE_EFFECT_CONTROLLER_H
#define ANDROID_SURFACE_EFFECT_CONTROLLER_H

#include <stdint.h>
#include <sys/types.h>
#include <ui/Rect.h>
#include <utils/List.h>
#include <utils/Singleton.h>
#include <utils/SortedVector.h>
#include <map>
#include <set>

#include "Animator.h"
#include "DisplayHardware/HWComposer.h"
#include "Effect.h"
#include "EffectFBOCache.h"
#include "RenderEngine/Texture.h"
#include "SurfaceFlinger.h"
#include "Transform.h"

#define SF_EFFECTS_HWC_MAX_DOWNSCALE 1

namespace android {

class BufferLayer;
class Mesh;
class DisplayDevice;
class EffectFBOCache;
class EffectsRenderEngine;
class Region;
class RenderArea;

#define SUPPRESS_UNUSED(expr) \
    do {                      \
        (void)(expr);         \
    } while (0)

class EffectController : public RefBase {
    friend class Effect;
    friend class BlurEffect;

public:
    EffectController(const SurfaceFlinger& flinger, const DisplayDevice& hw);
    ~EffectController();

    const DisplayDevice& getDisplayDevice() const { return mHW; }
    void setRenderArea(RenderArea* r) { mRenderArea = r; }
    EffectsRenderEngine& getEffectsRenderEngine() const { return mEngine; }

    bool prepareCommon(const Vector<sp<Layer> >& layersSortedByZ);
    bool prepare(const Vector<sp<Layer> >& layersSortedByZ);
    void prepareCompleted(const Vector<sp<Layer> >& layersSortedByZ) const;

    void composeLayer(const android::Layer& layer, const Mesh& mesh, int index);

    void setContentUpdatedForScreenshot();
    bool setPerFrameData(Layer& layer, int index);

    bool notInRender(const sp<Layer>& layer) const;
    bool shouldBeRenderedTwice(const sp<Layer>& layer) const;

    void setCaptureParams(uint32_t width, uint32_t height, const Rect& sourceRect,
                          uint32_t raHeight, Transform::orientation_flags orientation);
    void enableCapture(uint32_t fbName, uint32_t fbTexName);
    void disableCapture();

    Rect getEffectRegionHW(const Layer& layer) const;
    sp<GraphicBuffer> getBufferForHWC(const Layer& layer) const;

private:
    bool setEffectConsistency(const Vector<sp<Layer> >& layersSortedByZ) const;
    bool needExtraFBO(const Vector<sp<Layer> >& layersSortedByZ) const;
    bool checkReuseFBOs(const Vector<sp<Layer> >& layersSortedByZ, bool biggerFboIsRequired);
    void checkReuseCompositionFBOs(const Vector<sp<Layer> >& effectLayersSortedByZ,
                                   bool biggerFboIsRequired);
    void checkReuseSavedFBOs(const Vector<sp<Layer> >& effectLayersSortedByZ);

private:
    void initFBOs(int fboWidth, bool keepBiggerFbo, bool extraFbo);
    void clearFBOs();
    void saveEffectFBO(const Layer& layer, const SEffectFBOCacheItem& item,
                       const SEffectFBOCacheItem& itemForHWC);
    EffectFBOCache& getFboCache() { return mFBOCache; }
    void takeEffectFbo(const Layer& layer, SEffectFBOCacheItem& item,
                       SEffectFBOCacheItem& itemForHWC);

    void bindFboOutput();
    void bindDefaultOutput();
    void bindOutput(EffectOutput output);
    bool bindOutputEx(EffectOutput output);
    void swapFBOs();
    void clearFBOOutput();
    bool isFBOEmpty() const { return mFBOIsEmpty; }

    void resetTexture();
    void setupFboTexture(const SEffectFBOCacheItem& fbo, bool filtering);
    void setupTexture(const Texture& texture);
    void setupDefaultFboTexture(bool filtering);
    void setupExtraFboTexture(bool filtering);
    const Texture& getCurrentTexture() const { return mCurrentFboTexture; }

    void setViewportAndProjection(EffectOutput output) const;
    void setScissor(const Rect& rect, EffectOutput output) const;
    void resetProjection() const;

    bool isCaptureEnabled() const { return mCaptureFbName != 0; }

    void drawMesh(const Layer& layer, const Mesh& mesh);

private:
    static constexpr bool DEBUG = false;
    static constexpr bool DEBUG_REUSE = DEBUG;
    static constexpr bool DEBUG_CONSISTENCY = DEBUG;

    EffectsRenderEngine& mEngine;

public:
    const DisplayDevice& mHW;
    RenderArea* mRenderArea;

private:
    EffectFBOCache mFBOCache;

    // FBO for effects rendering
    // Normal layer content
    SEffectFBOCacheItem mFbo;
    // Extra FBO for advance rendering (not always used nor allocated)
    SEffectFBOCacheItem mFboEx;
    int mFboDownscaleFactor{1};

    bool mFBOIsEmpty;
    Texture mCurrentFboTexture;
    int mVphOffset{0}; // DDI fix: translates the rendering rectangle to the top left corner

    using EffectRegionsMap = std::map<const Layer*, Rect>;
    EffectRegionsMap mEffectRegionsMap;

    // Save FBO functions
    // NOTE: We use pointers here because we dont want to hold layers and avoid layer destructions
    struct FboCacheEntry {
        SEffectFBOCacheItem fbo;
        SEffectFBOCacheItem fboForHWC;
    };

    using SavedFBOMap = std::map<const Layer*, FboCacheEntry>;
    using NotInRenderMap = std::map<const Layer*, const Layer*>;
    using CompositionDependencyList = std::vector<const Layer*>;
    using ReuseDependencyMap = std::map<const Layer*, CompositionDependencyList>;

    SavedFBOMap mSaveFBO;      // This contains the last content from the Effects
    NotInRenderMap mNotRender; // These layers that do not need render, second parameter are the
                               // causing layer
    ReuseDependencyMap
            mReuseDependencies; // Dependant layers of Effect layers for the reuse mechanism
    CompositionDependencyList
            mCompositionDependencies; // Layer that took part in the composition FBO
    const SurfaceFlinger& mFlinger;
    bool getDisableHWC() const;

    // Screen capture
    uint32_t mCaptureFbName;
    uint32_t mCaptureTexFbName;
    uint32_t mCaptureReqWidth;
    uint32_t mCaptureReqHeight;
    Rect mCaptureSourceRect;
    uint32_t mCaptureReqRaHeight;
    Transform::orientation_flags mCaptureOrientation;
};

}; // namespace android

#endif // ANDROID_SURFACE_FLINGER_H
