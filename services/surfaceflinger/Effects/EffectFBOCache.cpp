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

#include "EffectFBOCache.h"
#include "RenderEngine/EffectsRenderEngine.h"
#include "SurfaceFlinger.h"

namespace android {

// TODO: make sure there aren't concurrent calls
// TODO: keep one fullscreen fbo always in memory.
// TODO: keep couple of small fbos always in memory

EffectFBOCache::EffectFBOCache(EffectsRenderEngine& engine) : mEngine(engine) {}

EffectFBOCache::~EffectFBOCache() {
    clear();
}

void EffectFBOCache::clear(void) {
    for (std::list<SEffectFBOCacheItem>::iterator i = mCache.begin(); i != mCache.end(); i++) {
        mEngine.releaseFramebufferGB(i->tex, i->name, i->imageKHR);
        ALOGD_IF(DEBUG, "EffectFBOCache(%p) clear: remove fbo name=%d", this, i->name);
    }
    mCache.clear();
}

void EffectFBOCache::recycle(const SEffectFBOCacheItem& item) {
    if (!item.isValid()) {
        return;
    }
    mCache.push_back(item);
    if (mCache.size() > EFFECT_FBO_CACHE_MAX_ITEMS) {
        const SEffectFBOCacheItem& item = mCache.front();
        mEngine.releaseFramebufferGB(item.tex, item.name, item.imageKHR);
        ALOGD_IF(DEBUG, "EffectFBOCache(%p) recycle: remove fbo name=%d", this,
                 mCache.front().name);
        mCache.pop_front();
    }
    ALOGD_IF(DEBUG,
             "EffectFBOCache(%p) recycle: size=%d, name=%d, w=%d, h=%d, imageKHR=%p, buffer=%p, "
             "status=%d",
             this, (int)mCache.size(), item.name, item.w, item.h, item.imageKHR, item.buffer.get(),
             item.status);
}

SEffectFBOCacheItem EffectFBOCache::get(uint32_t width, uint32_t height, bool bufferIsRequired) {
    for (auto it = mCache.begin(); it != mCache.end(); it++) {
        if (it->w == width && it->h == height && it->hasBuffer() == bufferIsRequired) {
            SEffectFBOCacheItem item(*it);
            mCache.erase(it);
            ALOGD_IF(DEBUG,
                     "EffectFBOCache(%p) get: reuse fbo size=%d, name=%d, w=%d, h=%d, imageKHR=%p, "
                     "buffer=%p, status=%d",
                     this, (int)mCache.size(), item.name, item.w, item.h, item.imageKHR,
                     item.buffer.get(), item.status);
            return item;
        }
    }

    SEffectFBOCacheItem item{width, height, 0, 0, EGL_NO_IMAGE_KHR, nullptr, 0};
    if (bufferIsRequired) {
        mEngine.createFramebufferGB(item.w, item.h, &item.tex, &item.name, &item.imageKHR,
                                    &item.buffer, &item.status);
    } else {
        mEngine.createFramebuffer(item.w, item.h, &item.tex, &item.name, &item.status);
    }

    ALOGD_IF(DEBUG,
             "EffectFBOCache(%p) get: create fbo name=%d, w=%d, h=%d, imageKHR=%p, buffer=%p, "
             "status=%d",
             this, item.name, item.w, item.h, item.imageKHR, item.buffer.get(), item.status);
    return item;
}

} // namespace android
