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

#ifndef ANDROID_EFFECTFBOCACHE_H
#define ANDROID_EFFECTFBOCACHE_H

#include <EGL/egl.h>
#include <EGL/eglext.h>
#include <stdint.h>
#include <ui/Fence.h>
#include <ui/GraphicBuffer.h>
#include <utils/RefBase.h>
#include <utils/StrongPointer.h>
#include <list>

#define EFFECT_FBO_CACHE_MAX_ITEMS 10

namespace android {
class EffectsRenderEngine;
class EffectFBOCache;
class SEffectFBOCacheItem;

class EffectFBOCache {
private:
    EffectsRenderEngine& mEngine;
    std::list<SEffectFBOCacheItem> mCache;
    static constexpr bool DEBUG = false;

public:
    EffectFBOCache(EffectsRenderEngine& engine);
    ~EffectFBOCache();

    void clear(void);
    void recycle(const SEffectFBOCacheItem& item);
    SEffectFBOCacheItem get(uint32_t width, uint32_t height, bool bufferIsRequired = false);
};

class SEffectFBOCacheItem {
    friend class EffectFBOCache;

public:
    SEffectFBOCacheItem() : w(0), h(0), tex(0), name(0), status(0) {}

    SEffectFBOCacheItem(uint32_t w, uint32_t h, uint32_t tex, uint32_t name, EGLImageKHR imageKHR,
                        sp<GraphicBuffer> buffer, uint32_t status)
          : w(w), h(h), tex(tex), name(name), imageKHR(imageKHR), buffer(buffer), status(status) {}

    inline void swap(SEffectFBOCacheItem& o) {
        std::swap(w, o.w);
        std::swap(h, o.h);
        std::swap(tex, o.tex);
        std::swap(name, o.name);
        std::swap(imageKHR, o.imageKHR);
        std::swap(buffer, o.buffer);
        std::swap(status, o.status);
    }

    inline void reset() {
        SEffectFBOCacheItem tmp;
        swap(tmp);
    }

    inline void recycle(EffectFBOCache& cache) {
        cache.recycle(*this);
        reset();
    }

    inline SEffectFBOCacheItem transfer() {
        SEffectFBOCacheItem tmp(*this);
        reset();
        return tmp;
    }

    uint32_t getWidth() const { return w; }
    uint32_t getHeight() const { return h; }
    uint32_t getTexName() const { return tex; }
    uint32_t getName() const { return name; }
    EGLImageKHR getImageKHR() const { return imageKHR; }
    sp<GraphicBuffer> getBuffer() const { return buffer; }
    bool hasBuffer() const { return buffer != nullptr; }
    uint32_t getStatus() const { return status; }
    bool isValid() const { return tex != 0; }

private:
    uint32_t w;
    uint32_t h;
    uint32_t tex;
    uint32_t name;
    EGLImageKHR imageKHR{EGL_NO_IMAGE_KHR};
    sp<GraphicBuffer> buffer;
    uint32_t status;
};

}; // namespace android

#endif // ANDROID_EFFECTFBOCACHE_H
