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

#include "EffectsRenderEngine.h"
#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <ui/GraphicBuffer.h>
#include "Mesh.h"

#include <GLES2/gl2.h>
#include <GLES2/gl2ext.h>

#define PI 3.1415f

// ---------------------------------------------------------------------------
namespace android {
// ---------------------------------------------------------------------------

void EffectsRenderEngine::setViewportAndProjection(size_t vpw, size_t vph, Rect sourceCrop,
                                                   size_t hwh, bool yswap,
                                                   Transform::orientation_flags rotation) {
    base::setViewportAndProjection(vpw, vph, sourceCrop, hwh, yswap, rotation);

    if (mProjectionType == EffectsRenderEngine::ACT3D_PROJECTION_PERSPECTIVE) {
        mState.setProjectionMatrix(get3DPerspectiveMatrix(sourceCrop, hwh, yswap));
    }
}

mat4 EffectsRenderEngine::get3DPerspectiveMatrix(Rect sourceCrop, size_t h, bool yswap) {
    mat4 m;
    float w = sourceCrop.right;
    float mZNear = 0.5f;
    float mZFar = 10000.0f;
    float mFOV = 30.0f;
    float tangent = tan(PI / 180.0f * mFOV / 2.0f);
    // float mDefaultX    = -((float) w / 2.0f);  // not used
    // float mDefaultY    = -((float) h / 2.0f);  // not used
    // float mDefaultZ    = -(((float) h / 2.0f) / tangent);  // not used
    float mAspectRatio = ((float)w) / ((float)h);
    float mBottom = tangent * mZNear * 2; // tan(FOV/2) = (top/2)    / zNear
    float mRight = mAspectRatio * mBottom;

    mBottom = mBottom / 2.0f;
    mRight = mRight / 2.0f;
    float mLeft = -mRight;
    float mTop = -mBottom;

    if (yswap) {
        m = mat4::frustum(mLeft, mRight, mBottom, mTop, mZNear, mZFar);
    } else {
        m = mat4::frustum(mLeft, mRight, mTop, mBottom, mZNear, mZFar);
    }
    return m;
}

Mesh& EffectsRenderEngine::makeRectangleMesh(uint32_t width, uint32_t height, Mesh& outMesh) const {
    Mesh::VertexArray<vec2> position(outMesh.getPositionArray<vec2>());
    Mesh::VertexArray<vec2> texCoord(outMesh.getTexCoordArray<vec2>());

    position[0] = vec2(0.0f, 0.0f);
    position[1] = vec2(width, 0.0f);
    position[2] = vec2(width, height);
    position[3] = vec2(0.0f, height);

    texCoord[0] = vec2(0.0f, 0.0f);
    texCoord[1] = vec2(1.0f, 0.0f);
    texCoord[2] = vec2(1.0f, 1.0f);
    texCoord[3] = vec2(0.0f, 1.0f);
    return outMesh;
}

Mesh& EffectsRenderEngine::scaleRectangleMesh(const Mesh& mesh, float scaleX, float scaleY,
                                              Mesh& outMesh) const {
    Mesh::VertexArray<vec2> position(outMesh.getPositionArray<vec2>());
    Mesh::VertexArray<vec2> texCoord(outMesh.getTexCoordArray<vec2>());

    if (mesh.getVertexCount() == 4) {
        position[0] = vec2(mesh.getPositions()[0 * mesh.getStride()] * scaleX,
                           mesh.getPositions()[0 * mesh.getStride() + 1] * scaleY);
        position[1] = vec2(mesh.getPositions()[1 * mesh.getStride()] * scaleX,
                           mesh.getPositions()[1 * mesh.getStride() + 1] * scaleY);
        position[2] = vec2(mesh.getPositions()[2 * mesh.getStride()] * scaleX,
                           mesh.getPositions()[2 * mesh.getStride() + 1] * scaleY);
        position[3] = vec2(mesh.getPositions()[3 * mesh.getStride()] * scaleX,
                           mesh.getPositions()[3 * mesh.getStride() + 1] * scaleY);

        if (mesh.getTexCoordsSize() == 2) {
            texCoord[0] = vec2(mesh.getTexCoords()[0 * mesh.getStride()],
                               mesh.getTexCoords()[0 * mesh.getStride() + 1]);
            texCoord[1] = vec2(mesh.getTexCoords()[1 * mesh.getStride()],
                               mesh.getTexCoords()[1 * mesh.getStride() + 1]);
            texCoord[2] = vec2(mesh.getTexCoords()[2 * mesh.getStride()],
                               mesh.getTexCoords()[2 * mesh.getStride() + 1]);
            texCoord[3] = vec2(mesh.getTexCoords()[3 * mesh.getStride()],
                               mesh.getTexCoords()[3 * mesh.getStride() + 1]);
        }
    }
    return outMesh;
}

void EffectsRenderEngine::createFramebuffer(uint32_t w, uint32_t h, uint32_t* fboTexName,
                                            uint32_t* fboName, uint32_t* status) {
    // write to framebuffer first
    GLuint tname, name;
    // create the texture
    glGenTextures(1, &tname);
    glBindTexture(GL_TEXTURE_2D, tname);
    glTexImage2D(GL_TEXTURE_2D, 0, GL_RGBA, w, h, 0, GL_RGBA, GL_UNSIGNED_BYTE, 0);

    // create a Framebuffer Object to render into
    glGenFramebuffers(1, &name);
    glBindFramebuffer(GL_FRAMEBUFFER, name);
    glFramebufferTexture2D(GL_FRAMEBUFFER, GL_COLOR_ATTACHMENT0, GL_TEXTURE_2D, tname, 0);

    // ignore texture
    glBindTexture(GL_TEXTURE_2D, 0);

    *status = glCheckFramebufferStatus(GL_FRAMEBUFFER);
    *fboTexName = tname;
    *fboName = name;
}

void EffectsRenderEngine::releaseFramebuffer(uint32_t texName, uint32_t fbName) {
    glBindFramebuffer(GL_FRAMEBUFFER, 0);
    glDeleteFramebuffers(1, &fbName);
    glDeleteTextures(1, &texName);
}

void EffectsRenderEngine::createFramebufferGB(uint32_t w, uint32_t h, uint32_t* fboTexName,
                                              uint32_t* fboName, EGLImageKHR* outImage,
                                              sp<GraphicBuffer>* outBuffer, uint32_t* status) {
    const PixelFormat format = PIXEL_FORMAT_RGBA_8888;
    const int usage = GraphicBuffer::USAGE_SW_WRITE_NEVER | GraphicBuffer::USAGE_SW_READ_NEVER |
            GraphicBuffer::USAGE_HW_TEXTURE | GraphicBuffer::USAGE_HW_RENDER |
            GraphicBuffer::USAGE_HW_COMPOSER;

    sp<GraphicBuffer> buffer = new GraphicBuffer(w, h, format, usage, "EffectFbo");

    EGLDisplay display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
    EGLClientBuffer clientBuffer = (EGLClientBuffer)buffer->getNativeBuffer();

    EGLImageKHR imageKHR = eglCreateImageKHR(display, EGL_NO_CONTEXT, EGL_NATIVE_BUFFER_ANDROID,
                                             clientBuffer, NULL);

    if (imageKHR == EGL_NO_IMAGE_KHR) {
        createFramebuffer(w, h, fboTexName, fboName, status);
        return;
    }

    bindImageAsFramebuffer(imageKHR, fboTexName, fboName, status);

    *outImage = imageKHR;
    *outBuffer = buffer;
}

void EffectsRenderEngine::releaseFramebufferGB(uint32_t texName, uint32_t fbName,
                                               EGLImageKHR image) {
    if (image != EGL_NO_IMAGE_KHR) {
        eglDestroyImageKHR(eglGetDisplay(EGL_DEFAULT_DISPLAY), image);
    }
    releaseFramebuffer(texName, fbName);
}

// ---------------------------------------------------------------------------
}; // namespace android
// ---------------------------------------------------------------------------
