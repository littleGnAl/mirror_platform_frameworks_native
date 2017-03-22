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

#ifndef INCLUDE_CALCFPS
#define INCLUDE_CALCFPS

#include <stdio.h>
#include <cutils/properties.h>
#include <cutils/log.h>
#include <utils/threads.h>
#include <utils/Vector.h>

#include "../Layer.h"           // needed only for debugging

#ifndef DEBUG_CALC_FPS_SF
#define CALCFPS_INIT() ((void)0)
#define CALCFPS_START() ((void)0)
#define CALCFPS_LAP(mDpy, mVisibleLayers) ((void)0)
#define CALCFPS_CACHEDCHK(mDpy, mVisibleLayers) ((void)0)
#else
#define CALCFPS_INIT() sfdutils::calcfps_init()
#define CALCFPS_START() sfdutils::calcfps_start()
#define CALCFPS_LAP(mDpy, mVisibleLayers) sfdutils::calcfps_lap(mDpy, mVisibleLayers)
#define CALCFPS_CACHEDCHK(mDpy, mVisibleLayers) sfdutils::calcfps_cachedFrameCheck(mDpy, mVisibleLayers)

using namespace android;
namespace sfdutils {
class CalcFps {
    public:
    CalcFps();
    ~CalcFps();

    void Init();
    void Fps(int dpy);
    void start(void);
    bool IsCached(void);
    void cachedFrameCheck(const Vector< sp<Layer> >& mVisibleLayers);

    private:
    static const unsigned int MAX_FPS_CALC_PERIOD_IN_FRAMES = 128;
    static const unsigned int MAX_FRAMEARRIVAL_STEPS = 50;
    static const unsigned int MAX_DEBUG_FPS_LEVEL = 2;
    static const int MAX_LAYER_HANDLE = 32;

    struct debug_fps_metadata_t {
        /* fps calculation based on time or number of frames */
        enum DfmType {
            DFM_FRAMES = 0,
            DFM_TIME   = 1,
        };

        DfmType type;

        /* indicates how much time do we wait till we calculate FPS */
        unsigned long time_period;

        /* indicates how much time elapsed since we report fps */
        float time_elapsed;

        /* indicates how many frames do we wait till we calculate FPS */
        unsigned int period;
        /* current frame, will go upto period, and then reset */
        unsigned int curr_frame;
        /* frame will arrive at a multiple of 16666 us at the display.
           This indicates how many steps to consider for our calculations.
           For example, if framearrival_steps = 10, then the frame that arrived
           after 166660 us or more will be ignored.
           */
        unsigned int framearrival_steps;
        /* ignorethresh_us = framearrival_steps * 16666 */
        nsecs_t      ignorethresh_us;
        /* used to calculate the actual frame arrival step, the times might not be
           accurate
           */
        unsigned int margin_us;

        /* actual data storage */
        nsecs_t      framearrivals[MAX_FPS_CALC_PERIOD_IN_FRAMES];
        nsecs_t      accum_framearrivals[MAX_FRAMEARRIVAL_STEPS];
    };

    private:
    void populate_debug_fps_metadata(void);
    void print_fps(float fps, int dpy);
    void calc_fps(nsecs_t currtime_us, int dpy);

    private:
    debug_fps_metadata_t mDebug_fps_metadata;
    unsigned int mDebug_fps_level;
    nsecs_t      mTcurr;
    bool         mIsCached;
    buffer_handle_t mPrev_hnd[MAX_LAYER_HANDLE];
};

void calcfps_init();
void calcfps_start();
void calcfps_lap(int mDpy, const Vector< sp<Layer> >& mVisibleLayers);
void calcfps_cachedFrameCheck(int mDpy, const Vector< sp<Layer> >& mVisibleLayers);
};//namespace sfdutils

#endif // DEBUG_CALC_FPS_SF

#endif // INCLUDE_CALCFPS
