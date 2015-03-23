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

#include <iostream>
#include <array>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

using std::array;
using std::cout;
using std::get;
using std::make_tuple;
using std::string;
using std::stringstream;
using std::swap;
using std::to_string;
using std::tuple;
using std::vector;

namespace android {

struct Color
{
    float red;
    float green;
    float blue;
    float alpha;

    bool operator==(const Color& other) const {
        return red == other.red &&
            green == other.green &&
            blue == other.blue &&
            alpha == other.alpha;
    }

    bool operator!=(const Color& other) const {
        return !(*this == other);
    }

    static const Color None;
    static const Color Red;
    static const Color Yellow;
    static const Color Green;
    static const Color Cyan;
    static const Color Blue;
    static const Color Magenta;
    static const Color White;
};

const Color Color::None{0.0f, 0.0f, 0.0f, 0.0f};
const Color Color::Red{1.0f, 0.0f, 0.0f, 1.0f};
const Color Color::Yellow{1.0f, 1.0f, 0.0f, 1.0f};
const Color Color::Green{0.0f, 1.0f, 0.0f, 1.0f};
const Color Color::Cyan{0.0f, 1.0f, 1.0f, 1.0f};
const Color Color::Blue{0.0f, 0.0f, 1.0f, 1.0f};
const Color Color::Magenta{1.0f, 0.0f, 1.0f, 1.0f};
const Color Color::White{1.0f, 1.0f, 1.0f, 1.0f};

struct GLRect
{
    GLRect(uint32_t inX, uint32_t inY, uint32_t squareWidth)
      : x(static_cast<int32_t>(inX)),
        y(static_cast<int32_t>(inY)),
        width(static_cast<int32_t>(squareWidth)),
        height(static_cast<int32_t>(squareWidth)) {}

    vector<EGLint> flatten() {
        return {x, y, width, height};
    }

    int32_t x;
    int32_t y;
    int32_t width;
    int32_t height;
};

static string getColorName(Color color) {
    if (color == Color::None) { return "None"; }
    else if (color == Color::Red) { return "Red"; }
    else if (color == Color::Yellow) { return "Yellow"; }
    else if (color == Color::Green) { return "Green"; }
    else if (color == Color::Cyan) { return "Cyan"; }
    else if (color == Color::Blue) { return "Blue"; }
    else if (color == Color::Magenta) { return "Magenta"; }
    else if (color == Color::White) { return "White"; }
    else { return "Unknown"; }
}

class StateTracker
{
  public:
    static const size_t NUM_POSITIONS = 5;
    static const size_t NUM_COLORS = 6;
    typedef array<Color, NUM_POSITIONS> ScreenContents;
    typedef vector<tuple<size_t, Color>> Damage;

    StateTracker()
      : mCurrentColor(0),
        mCurrentPosition(0),
        mScreenContents{Color::None},
        mPreviousContents{{Color::None}} {}

    void advanceState(size_t numSteps) {
        // Save previous state
        for (size_t prev = HISTORY_SIZE - 1; prev != 0; --prev) {
            mPreviousContents[prev] = move(mPreviousContents[prev - 1]);
        }
        mPreviousContents[0] = mScreenContents;

        // Update current state
        for (size_t step = 0; step < numSteps; ++step) {
            mScreenContents[mCurrentPosition] = sColors[mCurrentColor];
            mCurrentColor = (mCurrentColor + 1) % NUM_COLORS;
            mCurrentPosition = (mCurrentPosition + 1) % NUM_POSITIONS;
        }
    }

    const ScreenContents& getScreenContents() const {
        return mScreenContents;
    }

    Damage getBufferDamage(size_t age) const {
        if (age == 0 || (age - 1 >= HISTORY_SIZE)) {
            return asDamage(mScreenContents);
        }

        Damage damage;
        for (size_t p = 0; p < NUM_POSITIONS; ++p) {
            if (mScreenContents[p] != mPreviousContents[age - 1][p]) {
                damage.emplace_back(make_tuple(p, mScreenContents[p]));
            }
        }
        return damage;
    }

    Damage getSurfaceDamage() const {
        return getBufferDamage(1);
    }

  private:
    static const size_t HISTORY_SIZE = 3;

    static const array<Color, NUM_COLORS> sColors;

    static Damage asDamage(const ScreenContents& contents) {
        Damage damage;
        for (size_t p = 0; p < NUM_POSITIONS; ++p) {
            damage.emplace_back(make_tuple(p, contents[p]));
        }
        return damage;
    }

    size_t mCurrentColor;
    size_t mCurrentPosition;
    ScreenContents mScreenContents;
    array<ScreenContents, HISTORY_SIZE> mPreviousContents;
};

static_assert(StateTracker::NUM_COLORS == 6, "I only know 6 colors");
const array<Color, StateTracker::NUM_COLORS> StateTracker::sColors{
    Color::Red,
    Color::Yellow,
    Color::Green,
    Color::Cyan,
    Color::Blue,
    Color::Magenta,
};

typedef array<Color, StateTracker::NUM_POSITIONS> ScreenContents;

class Renderer
{
  public:
    Renderer()
      : mTracker(),
        mDisplay(EGL_NO_DISPLAY),
        mConfig(),
        mContext(EGL_NO_CONTEXT),
        mSurface(EGL_NO_SURFACE),
        mWidth(0),
        mHeight(0),
        mSquareWidth(0),
        mLeftMargin(0),
        mSurfaceControl(nullptr),
        mHasBufferAge(false),
        mHasSwapBuffersWithDamage(false),
        mHasPartialUpdate(false),
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

    void computeSquarePositions(uint32_t width, uint32_t height) {
        uint32_t numPartitions = 2 * StateTracker::NUM_POSITIONS + 1;
        mSquareWidth = width / numPartitions;
        uint32_t margin = width - (numPartitions - 2) * mSquareWidth;
        mLeftMargin = margin / 2;

        static const uint32_t VERTICAL_OFFSET = 50;
        static const uint32_t TOTAL_OFFSET = VERTICAL_OFFSET *
                (StateTracker::NUM_POSITIONS - 1);

        auto centerY = height / 2 - mSquareWidth / 2;
        for (size_t s = 0; s < StateTracker::NUM_POSITIONS; ++s) {
            auto x = mLeftMargin + s * (mSquareWidth * 2);
            auto y = centerY + TOTAL_OFFSET / 2 - VERTICAL_OFFSET * s;
            mSquarePositions.emplace_back(x, y, mSquareWidth);
        }
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

        computeSquarePositions(mWidth, mHeight);

        sp<SurfaceComposerClient> client = new SurfaceComposerClient;
        sp<SurfaceControl> surfaceControl = client->createSurface(
                String8("DirtyRect"), mWidth, mHeight,
                PIXEL_FORMAT_RGBA_8888, 0);

        if (surfaceControl == nullptr) {
            cout << "Unable to create surface\n";
            return nullptr;
        }

        SurfaceComposerClient::openGlobalTransaction();
        surfaceControl->setLayer(0x7fffffff);
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
        EGLint bufferAge = -1;
        if (mHasBufferAge) {
            eglQuerySurface(mDisplay, mSurface, EGL_BUFFER_AGE_EXT, &bufferAge);
            cout << "Current buffer age: " << to_string(bufferAge) << '\n';
        }

        bool flashSurfaceDamage = false;
        if (flashSurfaceDamage) {
            clearScreen();
            draw(mTracker.getScreenContents());
            draw(mTracker.getSurfaceDamage(), true);
            eglSwapBuffers(mDisplay, mSurface);
            usleep(250 * 1000);
        }

        bool flashBufferDamage = false;
        if (flashBufferDamage) {
            clearScreen();
            draw(mTracker.getScreenContents());
            draw(mTracker.getBufferDamage(static_cast<size_t>(bufferAge)), true);
            eglSwapBuffers(mDisplay, mSurface);
            usleep(250 * 1000);
        }

        if (bufferAge < 1) {
            clearScreen();
            draw(mTracker.getScreenContents());
        } else {
            auto bufferDamage =
                    mTracker.getBufferDamage(static_cast<size_t>(bufferAge));
            if (mHasPartialUpdate) {
                auto eglDamage = asEGL(bufferDamage);
                eglSetDamageRegionKHR(mDisplay, mSurface, eglDamage.data(),
                        static_cast<EGLint>(eglDamage.size()));
            }
            draw(bufferDamage, false);
        }

        static bool backgroundDrawn = false;
        if (backgroundDrawn && mHasSwapBuffersWithDamage) {
            cout << "Calling eglSwapBuffersWithDamageKHR\n";
            auto damage = asEGL(mTracker.getSurfaceDamage());
            eglSwapBuffersWithDamageKHR(mDisplay, mSurface,
                    damage.data(), damage.size() / 4);
        } else {
            cout << "Calling eglSwapBuffers\n";
            eglSwapBuffers(mDisplay, mSurface);
        }
        backgroundDrawn = true;

        mTracker.advanceState(2);
    }

  private:
    static void setIfFound(string extension, const char* name, bool& flag) {
        if (extension == name) {
            flag = true;
        }
    }

    static void printFound(bool flag, const char* name) {
        cout << (flag ? "Found " : "Didn't find ") << name << '\n';
    }

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
        while (getline(stream, extension, ' ')) {
            setIfFound(extension, "EGL_EXT_buffer_age", mHasBufferAge);
            setIfFound(extension, "EGL_KHR_swap_buffers_with_damage",
                    mHasSwapBuffersWithDamage);
            setIfFound(extension, "EGL_KHR_partial_update", mHasPartialUpdate);
        }

        printFound(mHasBufferAge, "EGL_EXT_buffer_age");
        printFound(mHasSwapBuffersWithDamage,
                "EGL_KHR_swap_buffers_with_damage");
        printFound(mHasPartialUpdate, "EGL_KHR_partial_update");


        if (mHasSwapBuffersWithDamage) {
            loadProc(eglSwapBuffersWithDamageKHR, "eglSwapBuffersWithDamageKHR");
        }

        if (mHasPartialUpdate) {
            loadProc(eglSetDamageRegionKHR, "eglSetDamageRegionKHR");
        }
    }

    void drawRect(GLRect position, Color color) {
        glEnable(GL_SCISSOR_TEST);
        glScissor(position.x, position.y, position.width, position.height);
        glClearColor(color.red, color.green, color.blue, color.alpha);
        glClear(GL_COLOR_BUFFER_BIT);
        glDisable(GL_SCISSOR_TEST);
    }

    void drawSquare(size_t id, Color color) {
        if (id >= mSquarePositions.size()) return;
        drawRect(mSquarePositions[id], color);
    }

    void draw(const StateTracker::ScreenContents& contents) {
        size_t squaresDrawn = 0;
        for (size_t p = 0; p < StateTracker::NUM_POSITIONS; ++p) {
            if (contents[p] != Color::None) {
                drawSquare(p, contents[p]);
                ++squaresDrawn;
            }
        }
        cout << "Drew " << to_string(squaresDrawn) << " squares\n";
    }

    void draw(const StateTracker::Damage& damage, bool overrideColor) {
        for (auto d : damage) {
            drawSquare(get<size_t>(d),
                    overrideColor ? Color::White : get<Color>(d));
        }
    }

    vector<EGLint> asEGL(const StateTracker::Damage& damage) {
        vector<EGLint> v;
        for (auto d : damage) {
            auto squareEGL = mSquarePositions[get<size_t>(d)].flatten();
            v.insert(v.end(), squareEGL.begin(), squareEGL.end());
        }
        return v;
    }

    StateTracker mTracker;
    EGLDisplay mDisplay;
    EGLConfig mConfig;
    EGLContext mContext;
    EGLSurface mSurface;
    uint32_t mWidth;
    uint32_t mHeight;
    uint32_t mSquareWidth;
    uint32_t mLeftMargin;
    vector<GLRect> mSquarePositions;
    sp<SurfaceControl> mSurfaceControl;
    bool mHasBufferAge;
    bool mHasSwapBuffersWithDamage;
    bool mHasPartialUpdate;
    PFNEGLSWAPBUFFERSWITHDAMAGEKHRPROC eglSwapBuffersWithDamageKHR;
    PFNEGLSETDAMAGEREGIONKHRPROC eglSetDamageRegionKHR;
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
        usleep(2000 * 1000);
    }

    // return EXIT_SUCCESS;
}
