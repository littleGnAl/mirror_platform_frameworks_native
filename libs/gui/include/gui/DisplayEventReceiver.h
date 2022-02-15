/*
 * Copyright (C) 2011 The Android Open Source Project
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

#ifndef ANDROID_GUI_DISPLAY_EVENT_H
#define ANDROID_GUI_DISPLAY_EVENT_H

#include <stdint.h>
#include <sys/types.h>

#include <utils/Errors.h>
#include <utils/RefBase.h>
#include <utils/Timers.h>

#include <binder/IInterface.h>
#include <gui/ISurfaceComposer.h>
#include <gui/VsyncEventData.h>

// ----------------------------------------------------------------------------

namespace android {

// ----------------------------------------------------------------------------

using gui::IDisplayEventConnection;
using gui::VsyncEventData;

namespace gui {
class BitTube;
} // namespace gui

static inline constexpr uint32_t fourcc(char c1, char c2, char c3, char c4) {
    return static_cast<uint32_t>(c1) << 24 |
        static_cast<uint32_t>(c2) << 16 |
        static_cast<uint32_t>(c3) << 8 |
        static_cast<uint32_t>(c4);
}

// ----------------------------------------------------------------------------
class DisplayEventReceiver {
public:

    enum {
        DISPLAY_EVENT_VSYNC = fourcc('v', 's', 'y', 'n'),
        DISPLAY_EVENT_HOTPLUG = fourcc('p', 'l', 'u', 'g'),
        DISPLAY_EVENT_MODE_CHANGE = fourcc('m', 'o', 'd', 'e'),
        DISPLAY_EVENT_NULL = fourcc('n', 'u', 'l', 'l'),
        DISPLAY_EVENT_FRAME_RATE_OVERRIDE = fourcc('r', 'a', 't', 'e'),
        DISPLAY_EVENT_FRAME_RATE_OVERRIDE_FLUSH = fourcc('f', 'l', 's', 'h'),
    };

    struct Event {
        // We add __attribute__((aligned(8))) for nsecs_t fields because
        // we need to make sure all fields are aligned the same with x86
        // and x64 (long long has different default alignment):
        //
        // https://en.wikipedia.org/wiki/Data_structure_alignment

        struct Header {
            uint32_t type;
            PhysicalDisplayId displayId __attribute__((aligned(8)));
            nsecs_t timestamp __attribute__((aligned(8)));
        };

        struct VSync {
            uint32_t count;
            nsecs_t expectedVSyncTimestamp __attribute__((aligned(8)));
            nsecs_t deadlineTimestamp __attribute__((aligned(8)));
            nsecs_t frameInterval __attribute__((aligned(8)));
            int64_t vsyncId;
            size_t preferredFrameTimelineIndex __attribute__((aligned(8)));
            struct FrameTimeline {
                nsecs_t expectedVSyncTimestamp __attribute__((aligned(8)));
                nsecs_t deadlineTimestamp __attribute__((aligned(8)));
                int64_t vsyncId;
            } frameTimelines[VsyncEventData::kFrameTimelinesLength];
        };

        struct Hotplug {
            bool connected;
        };

        struct ModeChange {
            int32_t modeId;
            nsecs_t vsyncPeriod __attribute__((aligned(8)));
        };

        struct FrameRateOverride {
            uid_t uid __attribute__((aligned(8)));
            float frameRateHz __attribute__((aligned(8)));
        };

        Header header;
        union {
            VSync vsync;
            Hotplug hotplug;
            ModeChange modeChange;
            FrameRateOverride frameRateOverride;
        };
    };

public:
    /*
     * DisplayEventReceiver creates and registers an event connection with
     * SurfaceFlinger. VSync events are disabled by default. Call setVSyncRate
     * or requestNextVsync to receive them.
     * To receive ModeChanged and/or FrameRateOverrides events specify this in
     * the constructor. Other events start being delivered immediately.
     */
    explicit DisplayEventReceiver(
            ISurfaceComposer::VsyncSource vsyncSource = ISurfaceComposer::eVsyncSourceApp,
            ISurfaceComposer::EventRegistrationFlags eventRegistration = {});

    /*
     * ~DisplayEventReceiver severs the connection with SurfaceFlinger, new events
     * stop being delivered immediately. Note that the queue could have
     * some events pending. These will be delivered.
     */
    ~DisplayEventReceiver();

    /*
     * initCheck returns the state of DisplayEventReceiver after construction.
     */
    status_t initCheck() const;

    /*
     * getFd returns the file descriptor to use to receive events.
     * OWNERSHIP IS RETAINED by DisplayEventReceiver. DO NOT CLOSE this
     * file-descriptor.
     */
    int getFd() const;

    /*
     * getEvents reads events from the queue and returns how many events were
     * read. Returns 0 if there are no more events or a negative error code.
     * If NOT_ENOUGH_DATA is returned, the object has become invalid forever, it
     * should be destroyed and getEvents() shouldn't be called again.
     */
    ssize_t getEvents(Event* events, size_t count);
    static ssize_t getEvents(gui::BitTube* dataChannel, Event* events, size_t count);

    /*
     * sendEvents write events to the queue and returns how many events were
     * written.
     */
    ssize_t sendEvents(Event const* events, size_t count);
    static ssize_t sendEvents(gui::BitTube* dataChannel, Event const* events, size_t count);

    /*
     * setVsyncRate() sets the Event::VSync delivery rate. A value of
     * 1 returns every Event::VSync. A value of 2 returns every other event,
     * etc... a value of 0 returns no event unless  requestNextVsync() has
     * been called.
     */
    status_t setVsyncRate(uint32_t count);

    /*
     * requestNextVsync() schedules the next Event::VSync. It has no effect
     * if the vsync rate is > 0.
     */
    status_t requestNextVsync();

    /**
     * getLatestVsyncEventData() gets the latest vsync event data.
     */
    status_t getLatestVsyncEventData(VsyncEventData* outVsyncEventData) const;

private:
    sp<IDisplayEventConnection> mEventConnection;
    std::unique_ptr<gui::BitTube> mDataChannel;
    std::optional<status_t> mInitError;
};

inline bool operator==(DisplayEventReceiver::Event::FrameRateOverride lhs,
                       DisplayEventReceiver::Event::FrameRateOverride rhs) {
    return (lhs.uid == rhs.uid) && std::abs(lhs.frameRateHz - rhs.frameRateHz) < 0.001f;
}

// ----------------------------------------------------------------------------
}; // namespace android

#endif // ANDROID_GUI_DISPLAY_EVENT_H
