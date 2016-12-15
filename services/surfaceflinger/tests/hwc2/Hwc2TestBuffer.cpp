/*
 * Copyright (C) 2016 The Android Open Source Project
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

#include <mutex>
#include <array>
#include <sstream>
#include <algorithm>

#include <gui/Surface.h>
#include <gui/BufferItemConsumer.h>
#include <gui/GraphicBufferAlloc.h>

#include <ui/GraphicBuffer.h>
#include <ui/vec4.h>

#include <GLES3/gl3.h>

#include "Hwc2TestBuffer.h"
#include "Hwc2TestLayers.h"

using namespace android;

typedef void (*FenceCallback)(int32_t fence, void* callbackArgs);

static void setBufferGeneratorFence(int32_t fence, void* bufferGenerator);
static void setTestBufferFence(int32_t fence, void* bufferGenerator);


class Hwc2TestSurfaceManager {
public:
    class BufferListener : public ConsumerBase::FrameAvailableListener {
    public:
        BufferListener(sp<IGraphicBufferConsumer> consumer,
                FenceCallback callback, void* callbackArgs)
            : mConsumer(consumer),
              mCallback(callback),
              mCallbackArgs(callbackArgs) { }

        void onFrameAvailable(const BufferItem& /*item*/)
        {
            BufferItem item;

            if (mConsumer->acquireBuffer(&item, 0))
                return;
            if (mConsumer->detachBuffer(item.mSlot))
                return;

            mCallback(item.mFence->dup(), mCallbackArgs);
        }

    private:
        sp<IGraphicBufferConsumer> mConsumer;
        FenceCallback mCallback;
        void* mCallbackArgs;
    };

    void initialize(int32_t bufferWidth, int32_t bufferHeight,
            android_pixel_format_t format, FenceCallback callback,
            void* callbackArgs)
    {
        sp<IGraphicBufferProducer> producer;
        sp<IGraphicBufferConsumer> consumer;
        BufferQueue::createBufferQueue(&producer, &consumer);

        consumer->setDefaultBufferSize(bufferWidth, bufferHeight);
        consumer->setDefaultBufferFormat(format);

        mBufferItemConsumer = new BufferItemConsumer(consumer,
                GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_HW_RENDER);

        mListener = new BufferListener(consumer, callback, callbackArgs);
        mBufferItemConsumer->setFrameAvailableListener(mListener);

        mSurface = new Surface(producer, true);
    }

    sp<Surface> getSurface() const
    {
        return mSurface;
    }

private:
    sp<BufferItemConsumer> mBufferItemConsumer;
    sp<BufferListener> mListener;
    sp<Surface> mSurface;
};


class Hwc2TestEglManager {
public:
    Hwc2TestEglManager()
        : mEglDisplay(EGL_NO_DISPLAY),
          mEglSurface(EGL_NO_SURFACE),
          mEglContext(EGL_NO_CONTEXT) { }

    ~Hwc2TestEglManager()
    {
        cleanup();
    }

    int initialize(sp<Surface> surface)
    {
        mSurface = surface;

        mEglDisplay = eglGetDisplay(EGL_DEFAULT_DISPLAY);
        if (mEglDisplay == EGL_NO_DISPLAY) return false;

        EGLint major;
        EGLint minor;
        if (!eglInitialize(mEglDisplay, &major, &minor)) {
            ALOGW("Could not initialize EGL");
            return false;
        }

        /* We're going to use a 1x1 pbuffer surface later on
         * The configuration doesn'distance really matter for what we're trying to
         * do */
        EGLint configAttrs[] = {
                EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
                EGL_RED_SIZE, 8,
                EGL_GREEN_SIZE, 8,
                EGL_BLUE_SIZE, 8,
                EGL_ALPHA_SIZE, 0,
                EGL_DEPTH_SIZE, 24,
                EGL_STENCIL_SIZE, 0,
                EGL_NONE
        };

        EGLConfig configs[1];
        EGLint configCnt;
        if (!eglChooseConfig(mEglDisplay, configAttrs, configs, 1,
                &configCnt)) {
            ALOGW("Could not select EGL configuration");
            eglReleaseThread();
            eglTerminate(mEglDisplay);
            return false;
        }

        if (configCnt <= 0) {
            ALOGW("Could not find EGL configuration");
            eglReleaseThread();
            eglTerminate(mEglDisplay);
            return false;
        }

        /* These objects are initialized below but the default "null" values are
         * used to cleanup properly at any point in the initialization sequence */
        EGLint attrs[] = { EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE };
        mEglContext = eglCreateContext(mEglDisplay, configs[0], EGL_NO_CONTEXT,
                attrs);
        if (mEglContext == EGL_NO_CONTEXT) {
            ALOGW("Could not create EGL context");
            cleanup();
            return false;
        }

        EGLint surfaceAttrs[] = { EGL_NONE };
        mEglSurface = eglCreateWindowSurface(mEglDisplay, configs[0],
                mSurface.get(), surfaceAttrs);
        if (mEglSurface == EGL_NO_SURFACE) {
            ALOGW("Could not create EGL surface");
            cleanup();
            return false;
        }

        if (!eglMakeCurrent(mEglDisplay, mEglSurface, mEglSurface, mEglContext)) {
            ALOGW("Could not change current EGL context");
            cleanup();
            return false;
        }

        return true;
    }

    void makeCurrent() const
    {
        eglMakeCurrent(mEglDisplay, mEglSurface, mEglSurface, mEglContext);
    }

    void present() const
    {
        eglSwapBuffers(mEglDisplay, mEglSurface);
    }

private:
    void cleanup()
    {
        if (mEglDisplay == EGL_NO_DISPLAY)
            return;
        if (mEglSurface != EGL_NO_SURFACE)
            eglDestroySurface(mEglDisplay, mEglSurface);
        if (mEglContext != EGL_NO_CONTEXT)
            eglDestroyContext(mEglDisplay, mEglContext);

        eglMakeCurrent(mEglDisplay, EGL_NO_SURFACE, EGL_NO_SURFACE,
                EGL_NO_CONTEXT);
        eglReleaseThread();
        eglTerminate(mEglDisplay);
    }

    sp<Surface> mSurface;
    EGLDisplay mEglDisplay;
    EGLSurface mEglSurface;
    EGLContext mEglContext;
};


static const std::array<vec2, 4> triangles = {{
    {  1.0f,  1.0f },
    { -1.0f,  1.0f },
    {  1.0f, -1.0f },
    { -1.0f, -1.0f },
}};

class Hwc2TestBufferGenerator {
public:

    ~Hwc2TestBufferGenerator()
    {
        mEglManager.makeCurrent();
    }

    int initialize(int32_t bufferWidth, int32_t bufferHeight)
    {
        mBufferWidth = bufferWidth;
        mBufferHeight = bufferHeight;
        mFormat = HAL_PIXEL_FORMAT_RGBA_8888;

        mSurfaceManager.initialize(mBufferWidth, mBufferHeight, mFormat,
                setBufferGeneratorFence, this);

        if (!mEglManager.initialize(mSurfaceManager.getSurface()))
            return -EINVAL;

        mEglManager.makeCurrent();

        glClearColor(0.0, 0.0, 0.0, 1.0);

        glEnableVertexAttribArray(0);

        status_t err;

        for (int i = 0; i < 2; i++)
            mGraphicBuffers.push_back(mGraphicBufferAlloc.createGraphicBuffer(
                    mBufferWidth, mBufferHeight, mFormat,
                    GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_HW_RENDER,
                    "hwc2_test_buffer", &err));

        return err;
    }

    /* It is not possible to simply generate a fence. The easiest way is to
     * generate a buffer using egl and use the associated fence. The buffer
     * cannot be guarenteed to be a certain format across all devices using this
     * method. Instead the buffer is generated using the CPU */
    int generateFence(FenceCallback callback, void* callbackArgs)
    {
        mCallback = callback;
        mCallbackArgs = callbackArgs;

        mEglManager.makeCurrent();

        glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 0, triangles.data());

        glClear(GL_COLOR_BUFFER_BIT);

        mEglManager.present();

        return 0;
    }

    void setFence(int32_t fence)
    {
        mCallback(fence, mCallbackArgs);
    }

    void setColor(int32_t x, int32_t y, android_pixel_format_t format,
            uint32_t stride, uint8_t* img, uint8_t r, uint8_t g, uint8_t b,
            uint8_t a)
    {
           switch (format) {
           case HAL_PIXEL_FORMAT_RGBA_8888:
               img[(y * stride + x) * 4 + 0] = r;
               img[(y * stride + x) * 4 + 1] = g;
               img[(y * stride + x) * 4 + 2] = b;
               img[(y * stride + x) * 4 + 3] = a;
               break;
           default:
               break;
           }
    }

    /* Guarentees the correct format across all devices */
    buffer_handle_t generateBuffer()
    {
        sp<GraphicBuffer> graphicBuffer = mGraphicBuffers.at(mNextGraphicBuffer);

        mNextGraphicBuffer++;
        if (mNextGraphicBuffer >= mGraphicBuffers.size())
            mNextGraphicBuffer = 0;

        if (graphicBuffer == nullptr)
            return nullptr;

        uint8_t* img;
        graphicBuffer->lock(GRALLOC_USAGE_SW_WRITE_OFTEN, (void**)(&img));

        uint32_t stride = graphicBuffer->getStride();

        for (int32_t y = 0; y < mBufferHeight; y++) {
            uint8_t max = 255;
            uint8_t min = 0;

            if (y < mBufferHeight * 1.0 / 3.0) {
                min = 255 * 1 / 2;
            } else if (y >= mBufferHeight * 2.0 / 3.0) {
                max = 255 * 1 / 2;
            }

            int32_t x = 0;
            for (; x < mBufferWidth / 3; x++)
                setColor(x, y, mFormat, stride, img, max, min, min, 255);

            for (; x < mBufferWidth * 2 / 3; x++)
                setColor(x, y, mFormat, stride, img, min, max, min, 255);

            for (; x < mBufferWidth; x++)
                setColor(x, y, mFormat, stride, img, min, min, max, 255);
        }

        graphicBuffer->unlock();

        return graphicBuffer->handle;
    }

private:
    Hwc2TestSurfaceManager mSurfaceManager;
    Hwc2TestEglManager mEglManager;

    int32_t mBufferWidth = -1;
    int32_t mBufferHeight = -1;
    android_pixel_format_t mFormat = static_cast<android_pixel_format_t>(0);

    FenceCallback mCallback = nullptr;
    void* mCallbackArgs = nullptr;

    GraphicBufferAlloc mGraphicBufferAlloc;
    std::vector<sp<GraphicBuffer>> mGraphicBuffers;
    size_t mNextGraphicBuffer = 0;
};


static void setBufferGeneratorFence(int32_t fence, void* bufferGenerator)
{
    static_cast<Hwc2TestBufferGenerator*>(bufferGenerator)->setFence(fence);
}

static void setTestBufferFence(int32_t fence, void* testBuffer)
{
    static_cast<Hwc2TestBuffer*>(testBuffer)->setFence(fence);
}


Hwc2TestBuffer::Hwc2TestBuffer()
    : mBufferGenerator() { }

Hwc2TestBuffer::~Hwc2TestBuffer()
{
    closeFence();
}

void Hwc2TestBuffer::updateBufferArea(int32_t bufferWidth,
        int32_t bufferHeight)
{
    if (mBufferWidth == bufferWidth && mBufferHeight == bufferHeight)
        return;

    mBufferWidth = bufferWidth;
    mBufferHeight = bufferHeight;
    mBufferGenerator.reset();
}

void Hwc2TestBuffer::setFence(int32_t fence)
{
    mFence = fence;
    mPending = true;

    mCv.notify_all();
}

int Hwc2TestBuffer::get(buffer_handle_t* outHandle, int32_t* outFence)
{
    if (mBufferWidth == -1 || mBufferHeight == -1)
        return -EINVAL;

    closeFence();

    if (!mBufferGenerator) {
        mBufferGenerator.reset(new Hwc2TestBufferGenerator());
        int ret = mBufferGenerator->initialize(mBufferWidth, mBufferHeight);
        if (ret)
            return ret;
    }

    std::unique_lock<std::mutex> lock(mMutex);

    while (mPending != false)
        if (mCv.wait_for(lock, std::chrono::seconds(2)) == std::cv_status::timeout)
            return -ETIME;

    int ret = mBufferGenerator->generateFence(setTestBufferFence, this);
    if (ret < 0)
        return ret;

    *outHandle = mBufferGenerator->generateBuffer();

    while (mPending != true)
        if (mCv.wait_for(lock, std::chrono::seconds(2)) == std::cv_status::timeout)
            return -ETIME;

    mPending = false;
    *outFence = dup(mFence);

    return 0;
}

void Hwc2TestBuffer::closeFence()
{
    if (mFence >= 0)
        close(mFence);
    mFence = -1;
}
