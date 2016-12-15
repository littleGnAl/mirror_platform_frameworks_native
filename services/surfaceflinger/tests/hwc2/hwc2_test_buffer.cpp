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

#include "hwc2_test_buffer.h"
#include "hwc2_test_layers.h"

using namespace android;

typedef void (*fence_callback)(int32_t fence, void *callback_args);

static void set_buffer_generator_fence(int32_t fence, void *buffer_generator);
static void set_test_buffer_fence(int32_t fence, void *buffer_generator);


class hwc2_test_surface_manager {
public:
    class buffer_listener : public ConsumerBase::FrameAvailableListener {
    public:
        buffer_listener(sp<IGraphicBufferConsumer> consumer,
                fence_callback callback, void *callback_args)
            : consumer(consumer),
              callback(callback),
              callback_args(callback_args) { }

        void onFrameAvailable(const BufferItem& /*item*/)
        {
            BufferItem item;

            if (consumer->acquireBuffer(&item, 0))
                return;
            if (consumer->detachBuffer(item.mSlot))
                return;

            callback(item.mFence->dup(), callback_args);
        }

    private:
        sp<IGraphicBufferConsumer> consumer;
        fence_callback callback;
        void *callback_args;
    };

    void initialize(int32_t buffer_width, int32_t buffer_height,
            android_pixel_format_t format, fence_callback callback,
            void *callback_args)
    {
        sp<IGraphicBufferProducer> producer;
        sp<IGraphicBufferConsumer> consumer;
        BufferQueue::createBufferQueue(&producer, &consumer);

        consumer->setDefaultBufferSize(buffer_width, buffer_height);
        consumer->setDefaultBufferFormat(format);

        buffer_item_consumer = new BufferItemConsumer(consumer,
                GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_HW_RENDER);

        listener = new buffer_listener(consumer, callback, callback_args);
        buffer_item_consumer->setFrameAvailableListener(listener);

        surface = new Surface(producer, true);
    }

    sp<Surface> get_surface() const
    {
        return surface;
    }

private:
    sp<BufferItemConsumer> buffer_item_consumer;
    sp<buffer_listener> listener;
    sp<Surface> surface;
};


class hwc2_test_egl_manager {
public:
    hwc2_test_egl_manager()
        : surface(),
          egl_display(EGL_NO_DISPLAY),
          egl_surface(EGL_NO_SURFACE),
          egl_context(EGL_NO_CONTEXT) { }

    ~hwc2_test_egl_manager()
    {
        cleanup();
    }

    int initialize(sp<Surface> surface)
    {
        this->surface = surface;

        egl_display = eglGetDisplay(EGL_DEFAULT_DISPLAY);
        if (egl_display == EGL_NO_DISPLAY) return false;

        EGLint major;
        EGLint minor;
        if (!eglInitialize(egl_display, &major, &minor)) {
            ALOGW("Could not initialize EGL");
            return false;
        }

        /* We're going to use a 1x1 pbuffer surface later on
         * The configuration doesn'distance really matter for what we're trying to
         * do */
        EGLint config_attrs[] = {
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
        EGLint config_count;
        if (!eglChooseConfig(egl_display, config_attrs, configs, 1,
                &config_count)) {
            ALOGW("Could not select EGL configuration");
            eglReleaseThread();
            eglTerminate(egl_display);
            return false;
        }

        if (config_count <= 0) {
            ALOGW("Could not find EGL configuration");
            eglReleaseThread();
            eglTerminate(egl_display);
            return false;
        }

        /* These objects are initialized below but the default "null" values are
         * used to cleanup properly at any point in the initialization sequence */
        EGLint attrs[] = { EGL_CONTEXT_CLIENT_VERSION, 2, EGL_NONE };
        egl_context = eglCreateContext(egl_display, configs[0], EGL_NO_CONTEXT,
                attrs);
        if (egl_context == EGL_NO_CONTEXT) {
            ALOGW("Could not create EGL context");
            cleanup();
            return false;
        }

        EGLint surface_attrs[] = { EGL_NONE };
        egl_surface = eglCreateWindowSurface(egl_display, configs[0],
                surface.get(), surface_attrs);
        if (egl_surface == EGL_NO_SURFACE) {
            ALOGW("Could not create EGL surface");
            cleanup();
            return false;
        }

        if (!eglMakeCurrent(egl_display, egl_surface, egl_surface, egl_context)) {
            ALOGW("Could not change current EGL context");
            cleanup();
            return false;
        }

        return true;
    }

    void make_current() const
    {
        eglMakeCurrent(egl_display, egl_surface, egl_surface, egl_context);
    }

    void present() const
    {
        eglSwapBuffers(egl_display, egl_surface);
    }

private:
    void cleanup()
    {
        if (egl_display == EGL_NO_DISPLAY)
            return;
        if (egl_surface != EGL_NO_SURFACE)
            eglDestroySurface(egl_display, egl_surface);
        if (egl_context != EGL_NO_CONTEXT)
            eglDestroyContext(egl_display, egl_context);

        eglMakeCurrent(egl_display, EGL_NO_SURFACE, EGL_NO_SURFACE,
                EGL_NO_CONTEXT);
        eglReleaseThread();
        eglTerminate(egl_display);
    }

    sp<Surface> surface;
    EGLDisplay egl_display;
    EGLSurface egl_surface;
    EGLContext egl_context;
};


static const std::array<vec2, 4> triangles = {{
    {  1.0f,  1.0f },
    { -1.0f,  1.0f },
    {  1.0f, -1.0f },
    { -1.0f, -1.0f },
}};

class hwc2_test_buffer_generator {
public:
    hwc2_test_buffer_generator()
        : surface_manager(),
          egl_manager(),
          buffer_width(-1),
          buffer_height(-1),
          format(static_cast<android_pixel_format_t>(0)),
          callback(nullptr),
          callback_args(nullptr),
          graphic_buffer_alloc(),
          graphic_buffers(),
          next_graphic_buffer(0) { }

    ~hwc2_test_buffer_generator()
    {
        egl_manager.make_current();
    }

    int initialize(int32_t buffer_width, int32_t buffer_height)
    {
        this->buffer_width = buffer_width;
        this->buffer_height = buffer_height;
        this->format = HAL_PIXEL_FORMAT_RGBA_8888;

        surface_manager.initialize(buffer_width, buffer_height, format,
                set_buffer_generator_fence, this);

        if (!egl_manager.initialize(surface_manager.get_surface()))
            return -EINVAL;

        egl_manager.make_current();

        glClearColor(0.0, 0.0, 0.0, 1.0);

        glEnableVertexAttribArray(0);

        status_t err;

        for (int i = 0; i < 2; i++)
            graphic_buffers.push_back(graphic_buffer_alloc.createGraphicBuffer(
                    buffer_width, buffer_height, format,
                    GRALLOC_USAGE_SW_READ_OFTEN | GRALLOC_USAGE_HW_RENDER,
                    "hwc2_test_buffer", &err));

        return err;
    }

    /* It is not possible to simply generate a fence. The easiest way is to
     * generate a buffer using egl and use the associated fence. The buffer
     * cannot be guarenteed to be a certain format across all devices using this
     * method. Instead the buffer is generated using the CPU */
    int generate_fence(fence_callback callback, void *callback_args)
    {
        this->callback = callback;
        this->callback_args = callback_args;

        egl_manager.make_current();

        glVertexAttribPointer(0, 2, GL_FLOAT, GL_FALSE, 0, triangles.data());

        glClear(GL_COLOR_BUFFER_BIT);

        egl_manager.present();

        return 0;
    }

    void set_fence(int32_t fence)
    {
        callback(fence, callback_args);
    }

    void set_color(int32_t x, int32_t y, android_pixel_format_t format,
            uint32_t stride, uint8_t *img, uint8_t r, uint8_t g, uint8_t b,
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
    buffer_handle_t generate_buffer()
    {
        sp<GraphicBuffer> graphic_buffer = get_next_graphic_buffer();

        if (graphic_buffer == nullptr)
            return nullptr;

        uint8_t *img;
        graphic_buffer->lock(GRALLOC_USAGE_SW_WRITE_OFTEN, (void **)(&img));

        uint32_t stride = graphic_buffer->getStride();

        for (int32_t y = 0; y < buffer_height; y++) {
            uint8_t max = 255;
            uint8_t min = 0;

            if (y < buffer_height * 1.0 / 3.0)
                min = 255 * 1 / 2;
            else if (y >= buffer_height * 2.0 / 3.0)
                max = 255 * 1 / 2;

            int32_t x = 0;
            for (; x < buffer_width / 3; x++)
                set_color(x, y, format, stride, img, max, min, min, 255);

            for (; x < buffer_width * 2 / 3; x++)
                set_color(x, y, format, stride, img, min, max, min, 255);

            for (; x < buffer_width; x++)
                set_color(x, y, format, stride, img, min, min, max, 255);
        }

        graphic_buffer->unlock();

        return graphic_buffer->handle;
    }

    /* Guarentees the correct format across all devices */
    buffer_handle_t generate_buffer(const hwc2_test_layers *test_layers,
            const std::set<hwc2_layer_t> *client_layers,
            const std::set<hwc2_layer_t> *clear_layers)
    {
        sp<GraphicBuffer> graphic_buffer = get_next_graphic_buffer();

        if (graphic_buffer == nullptr)
            return nullptr;

        uint8_t *img;
        graphic_buffer->lock(GRALLOC_USAGE_SW_WRITE_OFTEN, (void **)(&img));

        uint32_t stride = graphic_buffer->getStride();

        float df_l, df_t, df_r, df_b, df_w, df_h;
        float sc_l, sc_t;
        float df_w_div_sc_w;
        float df_h_div_sc_h;
        float x_pos, y_pos;
        float max, min;
        float tmp;
        hwc_transform_t transform;
        hwc2_blend_mode_t blend_mode;
        float plane_alpha;

        float bw_3 = buffer_width / 3;
        float bw_2_3 = buffer_width * 2 / 3;
        float bh_3 = buffer_height / 3;
        float bh_2_3 = buffer_height * 2 / 3;

        for (int32_t y = 0; y < buffer_height; y++) {
            for (int32_t x = 0; x < buffer_width; x++) {

                uint8_t r = 0, g = 0, b = 0;
                float a = 0.0f;

                for (auto layer = client_layers->rbegin();
                        layer != client_layers->rend(); ++layer) {

                    if (test_layers->get_composition(*layer)
                            != HWC2_COMPOSITION_CURSOR) {
                        hwc_rect_t display_frame = test_layers->get_display_frame(*layer);
                        df_l = display_frame.left;
                        df_t = display_frame.top;
                        df_r = display_frame.right;
                        df_b = display_frame.bottom;
                    } else {
                        auto &buffer_area = test_layers->get_buffer_area(*layer);
                        auto &cursor = test_layers->get_cursor(*layer);
                        df_l = cursor.first;
                        df_t = cursor.second;
                        df_r = cursor.first + buffer_area.first;
                        df_b = cursor.second + buffer_area.second;
                    }

                    if (x < df_l || x >= df_r || y < df_t || y >= df_b)
                        continue;

                    if (clear_layers->find(*layer) != clear_layers->end()) {
                        r = 0;
                        g = 0;
                        b = 0;
                        a = 0.0f;
                        continue;
                    }

                    if (test_layers->get_composition(*layer)
                            == HWC2_COMPOSITION_SOLID_COLOR) {
                        hwc_color_t color = test_layers->get_color(*layer);
                        r = color.r;
                        g = color.g;
                        b = color.b;
                        a = color.a * test_layers->get_plane_alpha(*layer);
                        continue;
                    }

                    x_pos = x;
                    y_pos = y;

                    transform = test_layers->get_transform(*layer);

                    df_w = df_r - df_l;
                    df_h = df_b - df_t;

                    if (transform > 0) {
                        /* Change origin */
                        x_pos = x_pos - df_l - df_w / 2.0;
                        y_pos = y_pos - df_t - df_h / 2.0;

                        /* Flip Horizontal */
                        if (transform & HWC_TRANSFORM_FLIP_H)
                            x_pos = -x_pos;

                        /* Flip vertical */
                        if (transform & HWC_TRANSFORM_FLIP_V)
                            y_pos = -y_pos;

                        /* Rotate 90 */
                        if (transform & HWC_TRANSFORM_ROT_90) {
                            tmp = x_pos;
                            x_pos = -y_pos * df_w / df_h;
                            y_pos = tmp * df_h / df_w;
                        }

                        /* Change origin back */
                        x_pos = x_pos + df_l + df_w / 2.0;
                        y_pos = y_pos + df_t + df_h / 2.0;
                    }

                    hwc_frect_t source_crop = test_layers->get_source_crop(*layer);
                    sc_l = source_crop.left;
                    sc_t = source_crop.top;

                    df_w_div_sc_w = df_w / (source_crop.right - sc_l);
                    df_h_div_sc_h = df_h / (source_crop.bottom - sc_t);

                    max = 255;
                    min = 0;

                    if (y_pos < ((bh_3) - sc_t) * df_h_div_sc_h + df_t)
                        min = 255 / 2;
                    else if (y_pos >= ((bh_2_3) - sc_t) * df_h_div_sc_h + df_t)
                        max = 255 / 2;

                    uint8_t r_cur = min, g_cur = min, b_cur = min;
                    float a_cur = 1.0f;

                    if (x_pos < ((bw_3) - sc_l) * (df_w_div_sc_w) + df_l)
                        r_cur = max;
                    else if (x_pos < ((bw_2_3) - sc_l) * (df_w_div_sc_w) + df_l)
                        g_cur = max;
                    else
                        b_cur = max;


                    blend_mode = test_layers->get_blend_mode(*layer);
                    plane_alpha = test_layers->get_plane_alpha(*layer);

                    if (blend_mode == HWC2_BLEND_MODE_PREMULTIPLIED) {
                        r_cur *= plane_alpha;
                        g_cur *= plane_alpha;
                        b_cur *= plane_alpha;
                    }

                    a_cur *= plane_alpha;

                    if (blend_mode == HWC2_BLEND_MODE_PREMULTIPLIED) {
                        r = r_cur + r * (1.0 - a_cur);
                        g = g_cur + g * (1.0 - a_cur);
                        b = b_cur + b * (1.0 - a_cur);
                        a = a_cur + a * (1.0 - a_cur);
                    } else if (blend_mode == HWC2_BLEND_MODE_COVERAGE) {
                        r = r_cur * a_cur + r * (1.0 - a_cur);
                        g = g_cur * a_cur + g * (1.0 - a_cur);
                        b = b_cur * a_cur + b * (1.0 - a_cur);
                        a = a_cur * a_cur + a * (1.0 - a_cur);
                    } else {
                        r = r_cur;
                        g = g_cur;
                        b = b_cur;
                        a = a_cur;
                    }
                }

                set_color(x, y, format, stride, img, r, g, b, a * 255);
            }
        }

        graphic_buffer->unlock();

        return graphic_buffer->handle;
    }

private:
    sp<GraphicBuffer> get_next_graphic_buffer()
    {
        sp<GraphicBuffer> graphic_buffer = graphic_buffers.at(next_graphic_buffer);

        next_graphic_buffer++;
        if (next_graphic_buffer >= graphic_buffers.size())
            next_graphic_buffer = 0;

        return graphic_buffer;
    }

    hwc2_test_surface_manager surface_manager;
    hwc2_test_egl_manager egl_manager;

    int32_t buffer_width;
    int32_t buffer_height;
    android_pixel_format_t format;

    fence_callback callback;
    void *callback_args;

    GraphicBufferAlloc graphic_buffer_alloc;
    std::vector<sp<GraphicBuffer>> graphic_buffers;
    size_t next_graphic_buffer;
};


static void set_buffer_generator_fence(int32_t fence, void *buffer_generator)
{
    static_cast<hwc2_test_buffer_generator *>(buffer_generator)->set_fence(fence);
}

static void set_test_buffer_fence(int32_t fence, void *test_buffer)
{
    static_cast<hwc2_test_buffer *>(test_buffer)->set_fence(fence);
}


hwc2_test_buffer::hwc2_test_buffer()
    : buffer_generator(),
      buffer_width(-1),
      buffer_height(-1),
      mutex(),
      cv(),
      pending(false),
      handle(nullptr),
      fence(-1) { }

hwc2_test_buffer::~hwc2_test_buffer()
{
    close_fence();
}

void hwc2_test_buffer::update_buffer_area(int32_t buffer_width,
        int32_t buffer_height)
{
    if (this->buffer_width == buffer_width
            && this->buffer_height == buffer_height)
        return;

    this->buffer_width = buffer_width;
    this->buffer_height = buffer_height;
    buffer_generator.reset();
}

void hwc2_test_buffer::set_fence(int32_t fence)
{
    this->fence = fence;
    pending = true;

    cv.notify_all();
}

int hwc2_test_buffer::get(buffer_handle_t *out_handle, int32_t *out_fence,
        const hwc2_test_layers *test_layers,
        const std::set<hwc2_layer_t> *client_layers,
        const std::set<hwc2_layer_t> *clear_layers)
{
    if (buffer_width == -1 || buffer_height == -1)
        return -EINVAL;

    close_fence();

    if (!buffer_generator) {
        buffer_generator.reset(new hwc2_test_buffer_generator());
        int ret = buffer_generator->initialize(buffer_width, buffer_height);
        if (ret)
            return ret;
    }

    std::unique_lock<std::mutex> lock(mutex);

    while (pending != false)
        if (cv.wait_for(lock, std::chrono::seconds(2)) == std::cv_status::timeout)
            return -ETIME;

    int ret = buffer_generator->generate_fence(set_test_buffer_fence, this);
    if (ret < 0)
        return ret;

    if (test_layers && client_layers && clear_layers)
        *out_handle = buffer_generator->generate_buffer(test_layers,
                client_layers, clear_layers);
    else
        *out_handle = buffer_generator->generate_buffer();

    while (pending != true)
        if (cv.wait_for(lock, std::chrono::seconds(2)) == std::cv_status::timeout)
            return -ETIME;

    pending = false;
    *out_fence = dup(fence);

    return 0;
}

void hwc2_test_buffer::close_fence()
{
    if (fence >= 0)
        close(fence);
    fence = -1;
}
