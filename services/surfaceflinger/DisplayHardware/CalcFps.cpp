/*
 * Copyright (C) 2017 The Android Open Source Project
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

// #define LOG_NDEBUG 0
#include <hardware/hwcomposer.h>
#include "CalcFps.h"
#include <inttypes.h>
#include <ui/GraphicBuffer.h>

#ifdef DEBUG_CALC_FPS_SF

namespace sfdutils {

CalcFps::CalcFps() :mDebug_fps_level(0), mTcurr(0), mIsCached(0) {
    Init();
}

CalcFps::~CalcFps() {
}

void CalcFps::Init() {
    char prop[PROPERTY_VALUE_MAX];
    property_get("debug.gr.calcfps_sf", prop, "0");

    mDebug_fps_level = atoi(prop);
    if (mDebug_fps_level > MAX_DEBUG_FPS_LEVEL) {
        ALOGW("[SF_FPS] out of range value for debug.gr.calcfps_sf, using 0");
        mDebug_fps_level = 0;
    }

    ALOGD("[SF_FPS] DEBUG_CALC_FPS: %d", mDebug_fps_level);
    if (mDebug_fps_level > 0) {
        populate_debug_fps_metadata();
    }
}

void CalcFps::Fps(int dpy) {
    if (mDebug_fps_level > 0) {
        calc_fps(ns2us(mTcurr), dpy);
    }
}

void CalcFps::populate_debug_fps_metadata(void)
{
    char prop[PROPERTY_VALUE_MAX];

    /* defaults calculation of fps to based on number of frames */
    property_get("debug.gr.calcfps_sf.type", prop, "0");
    mDebug_fps_metadata.type = (debug_fps_metadata_t::DfmType) atoi(prop);

    /* defaults to 1000ms */
    property_get("debug.gr.calcfps_sf.timeperiod", prop, "1000");
    mDebug_fps_metadata.time_period = atoi(prop);

    property_get("debug.gr.calcfps_sf.period", prop, "10");
    mDebug_fps_metadata.period = atoi(prop);

    if (mDebug_fps_metadata.period > MAX_FPS_CALC_PERIOD_IN_FRAMES) {
        mDebug_fps_metadata.period = MAX_FPS_CALC_PERIOD_IN_FRAMES;
    }

    /* default ignorethresh_us: 500 milli seconds */
    property_get("debug.gr.calcfps_sf.ignoreth_us", prop, "500000");
    mDebug_fps_metadata.ignorethresh_us = atoi(prop);

    mDebug_fps_metadata.framearrival_steps =
            (mDebug_fps_metadata.ignorethresh_us / 16666);

    if (mDebug_fps_metadata.framearrival_steps > MAX_FRAMEARRIVAL_STEPS) {
        mDebug_fps_metadata.framearrival_steps = MAX_FRAMEARRIVAL_STEPS;
        mDebug_fps_metadata.ignorethresh_us =
                mDebug_fps_metadata.framearrival_steps * 16666;
    }

    /* 2ms margin of error for the gettimeofday */
    mDebug_fps_metadata.margin_us = 2000;

    for (unsigned int i = 0; i < MAX_FRAMEARRIVAL_STEPS; i++) {
        mDebug_fps_metadata.accum_framearrivals[i] = 0;
    }

    mDebug_fps_metadata.curr_frame = 0;

    ALOGD("[SF_FPS] period: %d", mDebug_fps_metadata.period);
    ALOGD("[SF_FPS] ignorethresh_us: %" PRId64, mDebug_fps_metadata.ignorethresh_us);
}

void CalcFps::print_fps(float fps, int dpy)
{
    if (debug_fps_metadata_t::DFM_FRAMES == mDebug_fps_metadata.type) {
        ALOGD("[SF_FPS] DPY%d FPS for last %d frames: %3.2f", dpy, mDebug_fps_metadata.period, fps);
    }
    else {
        ALOGD("[SF_FPS] DPY%d FPS for last (%f ms, %d frames): %3.2f",
                dpy,
                mDebug_fps_metadata.time_elapsed,
                mDebug_fps_metadata.curr_frame, fps);
    }

    mDebug_fps_metadata.curr_frame = 0;
    mDebug_fps_metadata.time_elapsed = 0.0;

    if (mDebug_fps_level > 1) {
        ALOGD("[SF_FPS] DPY%d Frame Arrival Distribution:", dpy);
        for (unsigned int i = 0;
                i < ((mDebug_fps_metadata.framearrival_steps / 6) + 1);
                i++) {
            ALOGD("[SF_FPS] DPY%d %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64 " %" PRId64,
                    dpy,
                    mDebug_fps_metadata.accum_framearrivals[i*6],
                    mDebug_fps_metadata.accum_framearrivals[i*6+1],
                    mDebug_fps_metadata.accum_framearrivals[i*6+2],
                    mDebug_fps_metadata.accum_framearrivals[i*6+3],
                    mDebug_fps_metadata.accum_framearrivals[i*6+4],
                    mDebug_fps_metadata.accum_framearrivals[i*6+5]);
        }

        /* We are done with displaying, now clear the stats */
        for (unsigned int i = 0;
                i < mDebug_fps_metadata.framearrival_steps;
                i++) {
            mDebug_fps_metadata.accum_framearrivals[i] = 0;
        }
    }
    return;
}

void CalcFps::calc_fps(nsecs_t currtime_us, int dpy)
{
    static nsecs_t oldtime_us[3] = {0, 0, 0};

    nsecs_t diff = currtime_us - oldtime_us[dpy];

    oldtime_us[dpy] = currtime_us;

    if (debug_fps_metadata_t::DFM_FRAMES == mDebug_fps_metadata.type &&
        diff > mDebug_fps_metadata.ignorethresh_us) {
        return;
    }

    if (mDebug_fps_metadata.curr_frame < MAX_FPS_CALC_PERIOD_IN_FRAMES) {
        mDebug_fps_metadata.framearrivals[mDebug_fps_metadata.curr_frame] = diff;
    }

    mDebug_fps_metadata.curr_frame++;

    if (mDebug_fps_level > 1) {
        unsigned int currstep = (diff + mDebug_fps_metadata.margin_us) / 16666;

        if (currstep < mDebug_fps_metadata.framearrival_steps) {
            mDebug_fps_metadata.accum_framearrivals[currstep-1]++;
        }
    }

    if (debug_fps_metadata_t::DFM_FRAMES == mDebug_fps_metadata.type) {
        if (mDebug_fps_metadata.curr_frame == mDebug_fps_metadata.period) {
            /* time to calculate and display FPS */
            nsecs_t sum = 0;
            for (unsigned int i = 0; i < mDebug_fps_metadata.period; i++) {
                sum += mDebug_fps_metadata.framearrivals[i];
            }
            print_fps((mDebug_fps_metadata.period * float(1000000))/float(sum), dpy);
        }
    }
    else if (debug_fps_metadata_t::DFM_TIME == mDebug_fps_metadata.type) {
        mDebug_fps_metadata.time_elapsed += ((float)diff/1000.0);
        if (mDebug_fps_metadata.time_elapsed >= mDebug_fps_metadata.time_period) {
            float fps = (1000.0 * mDebug_fps_metadata.curr_frame)/
                    (float)mDebug_fps_metadata.time_elapsed;
            print_fps(fps, dpy);
        }
    }
    return;
}

void CalcFps::start(void) {
    if (mDebug_fps_level > 0) {
        mTcurr = systemTime();
    }
}

bool CalcFps::IsCached(void) {
    return mIsCached;
}

CalcFps fps[HWC_NUM_DISPLAY_TYPES];

void CalcFps::cachedFrameCheck(const Vector< sp<Layer> >& mVisibleLayers) {
    if (mDebug_fps_level <= 0) {
        return;
    }

    bool cached = true;

    const Vector<sp<Layer>>& currentLayers(mVisibleLayers);
    int layerCount = currentLayers.size();
    for (int i = 0; i < layerCount; i++) {
        const auto& layer = currentLayers[i];
        const sp<GraphicBuffer>& buffer(layer->getActiveBuffer());
        if (buffer != NULL) {
            if (mPrev_hnd[i] != buffer->handle) {
                cached = false;
                break;
            }
        }
    }

    for (int i = 0; i < layerCount; i++) {
        const auto& layer = currentLayers[i];
        const sp<GraphicBuffer>& buffer(layer->getActiveBuffer());
        if (buffer != NULL) {
            mPrev_hnd[i] = buffer->handle;
        }
    }

    if (layerCount > MAX_LAYER_HANDLE) {
        cached = true;
    }

    mIsCached = cached;

    return;
}

void calcfps_init() {
    for (int i = 0; i < HWC_NUM_DISPLAY_TYPES; i++) {
        fps[i].Init();
    }
}

void calcfps_start()
{
    for (int i = 0; i < HWC_NUM_DISPLAY_TYPES; i++) {
        fps[i].start();
    }
}

void calcfps_lap(int mDpy, const Vector< sp<Layer> >& mVisibleLayers)
{
    const Vector<sp<Layer>>& currentLayers(mVisibleLayers);
    if (currentLayers.size() > 0 && !fps[mDpy].IsCached()) {
        fps[mDpy].Fps(mDpy);
    }
}

void calcfps_cachedFrameCheck(int mDpy, const Vector< sp<Layer> >& mVisibleLayers) {
    fps[mDpy].cachedFrameCheck(mVisibleLayers);
    return;
}

};//namespace sfdutils

#endif
