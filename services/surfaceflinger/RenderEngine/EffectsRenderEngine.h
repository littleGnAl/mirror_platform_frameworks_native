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

#ifndef SF_EFFECTS_RENDERENGINE_H_
#define SF_EFFECTS_RENDERENGINE_H_

#include <math/mat4.h>
#include <stdint.h>
#include <ui/Rect.h>

#include "Description.h"
#include "GLES20RenderEngine.h"

// ---------------------------------------------------------------------------
namespace android {
// ---------------------------------------------------------------------------
class Mesh;
class RenderEngine;

class EffectsRenderEngine : public RE::impl::GLES20RenderEngine {
    using base = RE::impl::GLES20RenderEngine;

public:
    EffectsRenderEngine(uint32_t featureFlags) : RE::impl::GLES20RenderEngine(featureFlags) {}
    virtual ~EffectsRenderEngine() {}

#ifdef SEC_SUPPORT_DDISCALER
    virtual void setViewportAndProjection(size_t vpw, size_t vph, Rect sourceCrop, size_t hwh,
                                          bool yswap, Transform::orientation_flags rotation,
                                          int vphOffset = 0);
#else
    virtual void setViewportAndProjection(size_t vpw, size_t vph, Rect sourceCrop, size_t hwh,
                                          bool yswap, Transform::orientation_flags rotation);
#endif

    Mesh& makeRectangleMesh(uint32_t width, uint32_t height, Mesh& outMesh) const;
    Mesh& scaleRectangleMesh(const Mesh& mesh, float scaleX, float scaleY, Mesh& outMesh) const;

    enum { ACT3D_PROJECTION_PERSPECTIVE, ACT3D_PROJECTION_ORTHO };

    void setProjectionType(int pType) { mProjectionType = pType; }
    int getProjectionType() const { return mProjectionType; }

    mat4 get3DPerspectiveMatrix(Rect sourceCrop, size_t h, bool yswap);

    void createFramebuffer(uint32_t w, uint32_t h, uint32_t* fboTexName, uint32_t* fboName,
                           uint32_t* status);
    void releaseFramebuffer(uint32_t texName, uint32_t fbName);

    void createFramebufferGB(uint32_t w, uint32_t h, uint32_t* fboTexName, uint32_t* fboName,
                             EGLImageKHR* outImage, sp<GraphicBuffer>* outBuffer, uint32_t* status);
    void releaseFramebufferGB(uint32_t texName, uint32_t fbName, EGLImageKHR image);

private:
    int mProjectionType{ACT3D_PROJECTION_ORTHO};
};

// ---------------------------------------------------------------------------
}; // namespace android
// ---------------------------------------------------------------------------

#endif /* SF_EFFECTS_RENDERENGINE_H_ */
