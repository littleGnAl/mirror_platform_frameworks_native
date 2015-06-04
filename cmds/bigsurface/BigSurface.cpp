/*
 * Copyright 2015 The Android Open Source Project
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
 *
 */

#include <EGL/egl.h>
#include <GLES2/gl2.h>

#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>

#include <ui/DisplayInfo.h>

#include <utils/String8.h>

#include <cmath>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using std::cout;
using std::string;
using std::stringstream;
using std::swap;
using std::vector;

namespace android {

struct Color
{
    float red;
    float green;
    float blue;
    float alpha;
};

struct GLRect
{
    vector<EGLint> flatten() {
        return {x, y, width, height};
    }

    int32_t x;
    int32_t y;
    int32_t width;
    int32_t height;
};

class Renderer
{
  public:
    Renderer()
      : mDisplay(EGL_NO_DISPLAY),
        mConfig(),
        mContext(EGL_NO_CONTEXT),
        mSurface(EGL_NO_SURFACE),
        mWidth(0),
        mHeight(0),
        mVisibleRect(),
        mSurfaceControl(nullptr),
        mPhase(0.0),
        mColor{0.0f, 0.0f, 0.0f, 1.0f},
        eglSwapBuffersWithDamageKHR(nullptr) {}

    ~Renderer() {
        if (mDisplay != EGL_NO_DISPLAY) {
            eglMakeCurrent(mDisplay, EGL_NO_SURFACE, EGL_NO_SURFACE,
                    EGL_NO_CONTEXT);

            if (mContext != EGL_NO_CONTEXT) {
                eglDestroyContext(mDisplay, mContext);
            }

            if (mSurface != EGL_NO_SURFACE) {
                eglDestroySurface(mDisplay, mSurface);
            }
        }

        eglTerminate(mDisplay);
    }

    sp<SurfaceControl> getFullscreenSurface() {
        sp<IBinder> primaryDisplay = SurfaceComposerClient::getBuiltInDisplay(0);

        Vector<DisplayInfo> configs;
        status_t status = SurfaceComposerClient::getDisplayConfigs(
                primaryDisplay, &configs);
        if (status != NO_ERROR) {
            cout << "Unable to get display configs (" << status << ")\n";
            return nullptr;
        }

        size_t activeConfig = static_cast<size_t>(
                SurfaceComposerClient::getActiveConfig(primaryDisplay));

        mWidth = configs[activeConfig].w;
        mHeight = configs[activeConfig].h;

        if (configs[activeConfig].orientation & 0x01) {
            swap(mWidth, mHeight);
        }

        mVisibleRect = {OVERDRAW_PIXELS, OVERDRAW_PIXELS,
                static_cast<int32_t>(mWidth), static_cast<int32_t>(mHeight)};

        sp<SurfaceComposerClient> client = new SurfaceComposerClient;
        sp<SurfaceControl> surfaceControl = client->createSurface(
                String8("BigSurface"),
                mWidth + OVERDRAW_PIXELS * 2, mHeight + OVERDRAW_PIXELS * 2,
                PIXEL_FORMAT_RGBA_8888, 0);

        if (surfaceControl == nullptr) {
            cout << "Unable to create surface\n";
            return nullptr;
        }

        SurfaceComposerClient::openGlobalTransaction();
        surfaceControl->setLayer(0x7fffffff);
        surfaceControl->setPosition(-OVERDRAW_PIXELS, -OVERDRAW_PIXELS);
        surfaceControl->show();
        SurfaceComposerClient::closeGlobalTransaction();

        return surfaceControl;
    }

    bool initializeEgl() {
        cout << "Initializing EGL\n";

        mDisplay = eglGetDisplay(EGL_DEFAULT_DISPLAY);
        if (mDisplay == EGL_NO_DISPLAY) {
            cout << "Unable to get default display\n";
            return false;
        }

        EGLBoolean success = eglInitialize(mDisplay, NULL, NULL);
        if (success != EGL_TRUE) {
            EGLint error = eglGetError();
            cout << "Unable to initialize EGL (" << error << ")\n";
            return false;
        }

        EGLint configAttributes[] = {
            EGL_SURFACE_TYPE, EGL_WINDOW_BIT,
            EGL_RENDERABLE_TYPE, EGL_OPENGL_ES2_BIT,
            EGL_RED_SIZE, 8,
            EGL_GREEN_SIZE, 8,
            EGL_BLUE_SIZE, 8,
            EGL_ALPHA_SIZE, 8,
            EGL_NONE
        };
        EGLint numConfigs = 0;
        success = eglChooseConfig(mDisplay, configAttributes, &mConfig, 1,
                &numConfigs);
        if (success != EGL_TRUE) {
            EGLint error = eglGetError();
            cout << "Unable to choose config (" << error << ")\n";
            return false;
        }

        EGLint contextAttributes[] = {
            EGL_CONTEXT_CLIENT_VERSION, 2,
            EGL_NONE
        };
        mContext = eglCreateContext(mDisplay, mConfig, EGL_NO_CONTEXT,
                contextAttributes);
        if (mContext == EGL_NO_CONTEXT) {
            EGLint error = eglGetError();
            cout << "Unable to create context (" << error << ")\n";
            return false;
        }

        mSurfaceControl = getFullscreenSurface();
        if (mSurfaceControl == nullptr) {
            return false;
        }

        sp<ANativeWindow> window = mSurfaceControl->getSurface();
        mSurface = eglCreateWindowSurface(mDisplay, mConfig, window.get(),
                nullptr);
        if (mSurface == EGL_NO_SURFACE) {
            EGLint error = eglGetError();
            cout << "Unable to create window surface (" << error << ")\n";
            return false;
        }

        success = eglMakeCurrent(mDisplay, mSurface, mSurface, mContext);
        if (success != EGL_TRUE) {
            EGLint error = eglGetError();
            cout << "Unable to make current (" << error << ")\n";
            return false;
        }

        checkEglExtensions(mDisplay);

        cout << "Done initializing EGL\n";
        return true;
    }

    void clearScreen() {
        glClearColor(0.125f, 0.0f, 0.25f, 1.0f);
        glClear(GL_COLOR_BUFFER_BIT);
    }

    void render() {
        mPhase += (2 * PI) / 120;
        computeColor();

        clearScreen();
        draw();

        static bool backgroundDrawn = false;
        if (backgroundDrawn) {
            auto damage = mVisibleRect.flatten();
            eglSwapBuffersWithDamageKHR(mDisplay, mSurface,
                    damage.data(), damage.size() / 4);
        } else {
            eglSwapBuffers(mDisplay, mSurface);
        }
        backgroundDrawn = true;
    }

  private:
    static const int OVERDRAW_PIXELS = 200;
    static constexpr float PI = 3.14159265359f;

    template<typename T>
    static void loadProc(T& fp, const char* name) {
        fp = reinterpret_cast<T>(eglGetProcAddress(name));
    }

    void checkEglExtensions(EGLDisplay display) {
        if (display == EGL_NO_DISPLAY) {
            return;
        }

        const char* extensionString = eglQueryString(display, EGL_EXTENSIONS);
        if (extensionString == nullptr) {
            return;
        }

        cout << "Checking extensions\n";

        stringstream stream(extensionString);
        string extension;
        bool sbwdFound = false;
        while (getline(stream, extension, ' ')) {
            if (extension == "EGL_KHR_swap_buffers_with_damage") {
                sbwdFound = true;
            }
        }

        if (!sbwdFound) {
            cout << "swapBuffersWithDamage not found. Exiting.\n";
            exit(1);
        }

        loadProc(eglSwapBuffersWithDamageKHR, "eglSwapBuffersWithDamageKHR");
    }

    void computeColor() {
        mColor.red = static_cast<float>(sin(mPhase));
        mColor.green = static_cast<float>(sin(mPhase + (2 * PI) / 3));
        mColor.blue = static_cast<float>(sin(mPhase + (4 * PI) / 3));
    }

    void draw() {
        glEnable(GL_SCISSOR_TEST);
        glScissor(OVERDRAW_PIXELS, OVERDRAW_PIXELS,
                static_cast<int>(mWidth), static_cast<int>(mHeight));
        glClearColor(mColor.red, mColor.green, mColor.blue, mColor.alpha);
        glClear(GL_COLOR_BUFFER_BIT);
        glDisable(GL_SCISSOR_TEST);
    }

    EGLDisplay mDisplay;
    EGLConfig mConfig;
    EGLContext mContext;
    EGLSurface mSurface;
    uint32_t mWidth;
    uint32_t mHeight;
    GLRect mVisibleRect;
    sp<SurfaceControl> mSurfaceControl;
    float mPhase;
    Color mColor;
    PFNEGLSWAPBUFFERSWITHDAMAGEKHRPROC eglSwapBuffersWithDamageKHR;
};

} // namespace android

int main(int /* argc */, const char** /* argv */)
{
    android::Renderer renderer;
    if (!renderer.initializeEgl()) {
        return EXIT_FAILURE;
    }

    while (true) {
        renderer.render();
        usleep(16667);
    }

    // return EXIT_SUCCESS;
}
