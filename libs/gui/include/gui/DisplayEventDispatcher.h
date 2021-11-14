/*
 * Copyright (C) 2015 The Android Open Source Project
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

#include <gui/DisplayEventReceiver.h>
#include <utils/Log.h>
#include <utils/Looper.h>

namespace android {
using FrameRateOverride = DisplayEventReceiver::Event::FrameRateOverride;

struct VsyncEventData {
    // The Vsync Id corresponsing to this vsync event. This will be used to
    // populate ISurfaceComposer::setFrameTimelineVsync and
    // SurfaceComposerClient::setFrameTimelineVsync
    int64_t id = FrameTimelineInfo::INVALID_VSYNC_ID;

    // The deadline in CLOCK_MONOTONIC that the app needs to complete its
    // frame by (both on the CPU and the GPU)
    int64_t deadlineTimestamp = std::numeric_limits<int64_t>::max();

    // The current frame interval in ns when this frame was scheduled.
    int64_t frameInterval = 0;
};

class DisplayEventDispatcher : public LooperCallback {
public:
    explicit DisplayEventDispatcher(
            const sp<Looper>& looper,
            ISurfaceComposer::VsyncSource vsyncSource = ISurfaceComposer::eVsyncSourceApp,
            ISurfaceComposer::EventRegistrationFlags eventRegistration = {});

    status_t initialize();
    void dispose();
    status_t scheduleVsync();
    void injectEvent(const DisplayEventReceiver::Event& event);
    int getFd() const;
    virtual int handleEvent(int receiveFd, int events, void* data);

protected:
    virtual ~DisplayEventDispatcher() = default;

private:
    sp<Looper> mLooper;
    DisplayEventReceiver mReceiver;
    bool mWaitingForVsync;
    uint32_t mLastVsyncCount;
    nsecs_t mLastScheduleVsyncTime;

    std::vector<FrameRateOverride> mFrameRateOverrides;

    virtual void dispatchVsync(nsecs_t timestamp, PhysicalDisplayId displayId, uint32_t count,
                               VsyncEventData vsyncEventData) = 0;
    virtual void dispatchHotplug(nsecs_t timestamp, PhysicalDisplayId displayId,
                                 bool connected) = 0;
    virtual void dispatchModeChanged(nsecs_t timestamp, PhysicalDisplayId displayId, int32_t modeId,
                                     nsecs_t vsyncPeriod) = 0;
    // AChoreographer-specific hook for processing null-events so that looper
    // can be properly poked.
    virtual void dispatchNullEvent(nsecs_t timestamp, PhysicalDisplayId displayId) = 0;

    virtual void dispatchFrameRateOverrides(nsecs_t timestamp, PhysicalDisplayId displayId,
                                            std::vector<FrameRateOverride> overrides) = 0;

    bool processPendingEvents(nsecs_t* outTimestamp, PhysicalDisplayId* outDisplayId,
                              uint32_t* outCount, VsyncEventData* outVsyncEventData);
};
} // namespace android
