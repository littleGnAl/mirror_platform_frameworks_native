
#ifndef FUZZ_INPUTREADERHELPERS_H
#define FUZZ_INPUTREADERHELPERS_H

#include <CursorInputMapper.h>
#include <InputDevice.h>
#include <InputMapper.h>
#include <InputReader.h>
#include <KeyboardInputMapper.h>
#include <MultiTouchInputMapper.h>
#include <SingleTouchInputMapper.h>
#include <SwitchInputMapper.h>
#include <TouchInputMapper.h>
#include <map>

namespace android {
// An arbitrary time value.
static const nsecs_t ARBITRARY_TIME = 1234;
// Arbitrary display properties.
static const int32_t DISPLAY_ID = 0;
static const int32_t SECONDARY_DISPLAY_ID = DISPLAY_ID + 1;
static const int32_t DISPLAY_WIDTH = 480;
static const int32_t DISPLAY_HEIGHT = 800;
static const int32_t VIRTUAL_DISPLAY_ID = 1;
static const int32_t VIRTUAL_DISPLAY_WIDTH = 400;
static const int32_t VIRTUAL_DISPLAY_HEIGHT = 500;
static const char* VIRTUAL_DISPLAY_UNIQUE_ID = "virtual:1";
static constexpr std::optional<uint8_t> NO_PORT = std::nullopt; // no physical port is specified
// Error tolerance for floating point assertions.
static const float EPSILON = 0.001f;
template <typename T>
static inline T min(T a, T b) {
    return a < b ? a : b;
}
static inline float avg(float x, float y) {
    return (x + y) / 2;
}
// --- FakePointerController ---
class FakePointerController : public PointerControllerInterface {
    bool mHaveBounds;
    float mMinX, mMinY, mMaxX, mMaxY;
    float mX, mY;
    int32_t mButtonState;
    int32_t mDisplayId;

public:
    FakePointerController()
          : mHaveBounds(false),
            mMinX(0),
            mMinY(0),
            mMaxX(0),
            mMaxY(0),
            mX(0),
            mY(0),
            mButtonState(0),
            mDisplayId(ADISPLAY_ID_DEFAULT) {}

    virtual ~FakePointerController() {}

    void setBounds(float minX, float minY, float maxX, float maxY) {
        mHaveBounds = true;
        mMinX = minX;
        mMinY = minY;
        mMaxX = maxX;
        mMaxY = maxY;
    }

    virtual void setPosition(float x, float y) {
        mX = x;
        mY = y;
    }

    virtual void setButtonState(int32_t buttonState) { mButtonState = buttonState; }

    virtual int32_t getButtonState() const { return mButtonState; }

    virtual void getPosition(float* outX, float* outY) const {
        *outX = mX;
        *outY = mY;
    }

    virtual int32_t getDisplayId() const { return mDisplayId; }

    virtual void setDisplayViewport(const DisplayViewport& viewport) {
        mDisplayId = viewport.displayId;
    }

    const std::map<int32_t, std::vector<int32_t>>& getSpots() { return mSpotsByDisplay; }

private:
    virtual bool getBounds(float* outMinX, float* outMinY, float* outMaxX, float* outMaxY) const {
        *outMinX = mMinX;
        *outMinY = mMinY;
        *outMaxX = mMaxX;
        *outMaxY = mMaxY;
        return mHaveBounds;
    }

    virtual void move(float deltaX, float deltaY) {
        mX += deltaX;
        if (mX < mMinX) mX = mMinX;
        if (mX > mMaxX) mX = mMaxX;
        mY += deltaY;
        if (mY < mMinY) mY = mMinY;
        if (mY > mMaxY) mY = mMaxY;
    }

    virtual void fade(Transition) {}

    virtual void unfade(Transition) {}

    virtual void setPresentation(Presentation) {}

    virtual void setSpots(const PointerCoords*, const uint32_t*, BitSet32 spotIdBits,
                          int32_t displayId) {
        std::vector<int32_t> newSpots;
        // Add spots for fingers that are down.
        for (BitSet32 idBits(spotIdBits); !idBits.isEmpty();) {
            uint32_t id = idBits.clearFirstMarkedBit();
            newSpots.push_back(id);
        }

        mSpotsByDisplay[displayId] = newSpots;
    }

    virtual void clearSpots() {}

    std::map<int32_t, std::vector<int32_t>> mSpotsByDisplay;
};
// --- FakeInputReaderPolicy ---
class FakeInputReaderPolicy : public InputReaderPolicyInterface {
    InputReaderConfiguration mConfig;
    std::unordered_map<int32_t, std::shared_ptr<FakePointerController>> mPointerControllers;
    std::vector<InputDeviceInfo> mInputDevices;
    std::vector<DisplayViewport> mViewports;
    TouchAffineTransformation transform;

public:
    FakeInputReaderPolicy() {}
    virtual ~FakeInputReaderPolicy() {}

    virtual void clearViewports() {
        mViewports.clear();
        mConfig.setDisplayViewports(mViewports);
    }

    std::optional<DisplayViewport> getDisplayViewportByUniqueId(const std::string& uniqueId) const {
        return mConfig.getDisplayViewportByUniqueId(uniqueId);
    }
    std::optional<DisplayViewport> getDisplayViewportByType(ViewportType type) const {
        return mConfig.getDisplayViewportByType(type);
    }

    std::optional<DisplayViewport> getDisplayViewportByPort(uint8_t displayPort) const {
        return mConfig.getDisplayViewportByPort(displayPort);
    }

    void addDisplayViewport(int32_t displayId, int32_t width, int32_t height, int32_t orientation,
                            const std::string& uniqueId, std::optional<uint8_t> physicalPort,
                            ViewportType viewportType) {
        const DisplayViewport viewport =
                createDisplayViewport(displayId, width, height, orientation, uniqueId, physicalPort,
                                      viewportType);
        mViewports.push_back(viewport);
        mConfig.setDisplayViewports(mViewports);
    }

    void addExcludedDeviceName(const std::string& deviceName) {
        mConfig.excludedDeviceNames.push_back(deviceName);
    }

    void addInputPortAssociation(const std::string& inputPort, uint8_t displayPort) {
        mConfig.portAssociations.insert({inputPort, displayPort});
    }

    void addDisabledDevice(int32_t deviceId) {
        ssize_t index = mConfig.disabledDevices.indexOf(deviceId);
        bool currentlyEnabled = index < 0;
        if (currentlyEnabled) {
            mConfig.disabledDevices.add(deviceId);
        }
    }

    void removeDisabledDevice(int32_t deviceId) {
        ssize_t index = mConfig.disabledDevices.indexOf(deviceId);
        bool currentlyEnabled = index < 0;
        if (!currentlyEnabled) {
            mConfig.disabledDevices.remove(deviceId);
        }
    }

    void setPointerController(int32_t deviceId, std::shared_ptr<FakePointerController> controller) {
        mPointerControllers.insert_or_assign(deviceId, std::move(controller));
    }

    const InputReaderConfiguration* getReaderConfiguration() const { return &mConfig; }

    const std::vector<InputDeviceInfo>& getInputDevices() const { return mInputDevices; }

    TouchAffineTransformation getTouchAffineTransformation(const std::string& inputDeviceDescriptor,
                                                           int32_t surfaceRotation) {
        return transform;
    }

    void setTouchAffineTransformation(const TouchAffineTransformation t) { transform = t; }

    void setPointerCapture(bool enabled) { mConfig.pointerCapture = enabled; }

    void setShowTouches(bool enabled) { mConfig.showTouches = enabled; }

    void setDefaultPointerDisplayId(int32_t pointerDisplayId) {
        mConfig.defaultPointerDisplayId = pointerDisplayId;
    }

private:
    DisplayViewport createDisplayViewport(int32_t displayId, int32_t width, int32_t height,
                                          int32_t orientation, const std::string& uniqueId,
                                          std::optional<uint8_t> physicalPort, ViewportType type) {
        bool isRotated =
                (orientation == DISPLAY_ORIENTATION_90 || orientation == DISPLAY_ORIENTATION_270);
        DisplayViewport v;
        v.displayId = displayId;
        v.orientation = orientation;
        v.logicalLeft = 0;
        v.logicalTop = 0;
        v.logicalRight = isRotated ? height : width;
        v.logicalBottom = isRotated ? width : height;
        v.physicalLeft = 0;
        v.physicalTop = 0;
        v.physicalRight = isRotated ? height : width;
        v.physicalBottom = isRotated ? width : height;
        v.deviceWidth = isRotated ? height : width;
        v.deviceHeight = isRotated ? width : height;
        v.uniqueId = uniqueId;
        v.physicalPort = physicalPort;
        v.type = type;
        return v;
    }

    virtual void getReaderConfiguration(InputReaderConfiguration* outConfig) {
        *outConfig = mConfig;
    }

    virtual std::shared_ptr<PointerControllerInterface> obtainPointerController(int32_t deviceId) {
        return mPointerControllers[deviceId];
    }

    virtual void notifyInputDevicesChanged(const std::vector<InputDeviceInfo>& inputDevices) {
        mInputDevices = inputDevices;
    }

    virtual sp<KeyCharacterMap> getKeyboardLayoutOverlay(const InputDeviceIdentifier&) {
        return nullptr;
    }

    virtual std::string getDeviceAlias(const InputDeviceIdentifier&) { return ""; }
};
// --- FakeEventHub ---
class FakeEventHub : public EventHubInterface {
    struct KeyInfo {
        int32_t keyCode;
        uint32_t flags;
    };

    struct Device {
        InputDeviceIdentifier identifier;
        uint32_t classes;
        PropertyMap configuration;
        KeyedVector<int, RawAbsoluteAxisInfo> absoluteAxes;
        KeyedVector<int, bool> relativeAxes;
        KeyedVector<int32_t, int32_t> keyCodeStates;
        KeyedVector<int32_t, int32_t> scanCodeStates;
        KeyedVector<int32_t, int32_t> switchStates;
        KeyedVector<int32_t, int32_t> absoluteAxisValue;
        KeyedVector<int32_t, KeyInfo> keysByScanCode;
        KeyedVector<int32_t, KeyInfo> keysByUsageCode;
        KeyedVector<int32_t, bool> leds;
        std::vector<VirtualKeyDefinition> virtualKeys;
        bool enabled;

        status_t enable() {
            enabled = true;
            return OK;
        }

        status_t disable() {
            enabled = false;
            return OK;
        }

        explicit Device(uint32_t classes) : classes(classes), enabled(true) {}
    };

    std::map<int32_t, Device*> mDevices;
    std::vector<std::string> mExcludedDevices;
    List<RawEvent> mEvents;
    std::unordered_map<int32_t /*deviceId*/, std::vector<TouchVideoFrame>> mVideoFrames;

public:
    FakeEventHub() {}
    virtual ~FakeEventHub() {
        for (auto const& device : mDevices) {
            delete device.second;
        }
    }


    void addDevice(int32_t deviceId, const std::string& name, uint32_t classes) {
        Device* device = new Device(classes);

        if (device) {
            device->identifier.name = name;
            if (mDevices.find(deviceId) != mDevices.end()) {
                Device* device = mDevices.at(deviceId);
                delete device;
                mDevices.erase(deviceId);
            }
            mDevices.insert_or_assign(deviceId, device);

            enqueueEvent(ARBITRARY_TIME, deviceId, EventHubInterface::DEVICE_ADDED, 0, 0);
        }
    }

    void removeDevice(int32_t deviceId) {
        if (mDevices.find(deviceId) != mDevices.end()) {
            delete mDevices.at(deviceId);
            mDevices.erase(deviceId);

            enqueueEvent(ARBITRARY_TIME, deviceId, EventHubInterface::DEVICE_REMOVED, 0, 0);
        }
    }

    bool isDeviceEnabled(int32_t deviceId) {
        Device* device = getDevice(deviceId);
        if (device == nullptr) {
            ALOGE("Incorrect device id=%" PRId32 " provided to %s", deviceId, __func__);
            return false;
        }
        return device->enabled;
    }

    status_t enableDevice(int32_t deviceId) {
        status_t result;
        Device* device = getDevice(deviceId);
        if (device == nullptr) {
            ALOGE("Incorrect device id=%" PRId32 " provided to %s", deviceId, __func__);
            return BAD_VALUE;
        }
        if (device->enabled) {
            ALOGW("Duplicate call to %s, device %" PRId32 " already enabled", __func__, deviceId);
            return OK;
        }
        result = device->enable();
        return result;
    }

    status_t disableDevice(int32_t deviceId) {
        Device* device = getDevice(deviceId);
        if (device == nullptr) {
            ALOGE("Incorrect device id=%" PRId32 " provided to %s", deviceId, __func__);
            return BAD_VALUE;
        }
        if (!device->enabled) {
            ALOGW("Duplicate call to %s, device %" PRId32 " already disabled", __func__, deviceId);
            return OK;
        }
        return device->disable();
    }

    void finishDeviceScan() {
        enqueueEvent(ARBITRARY_TIME, 0, EventHubInterface::FINISHED_DEVICE_SCAN, 0, 0);
    }

    void addConfigurationProperty(int32_t deviceId, const String8& key, const String8& value) {
        Device* device = getDevice(deviceId);

        if (device) {
            device->configuration.addProperty(key, value);
        }
    }

    void addConfigurationMap(int32_t deviceId, const PropertyMap* configuration) {
        Device* device = getDevice(deviceId);

        if (device) {
            device->configuration.addAll(configuration);
        }
    }

    void addAbsoluteAxis(int32_t deviceId, int axis, int32_t minValue, int32_t maxValue, int flat,
                         int fuzz, int resolution = 0) {
        Device* device = getDevice(deviceId);

        if (device) {
            RawAbsoluteAxisInfo info;
            info.valid = true;
            info.minValue = minValue;
            info.maxValue = maxValue;
            info.flat = flat;
            info.fuzz = fuzz;
            info.resolution = resolution;
            device->absoluteAxes.add(axis, info);
        }
    }

    void addRelativeAxis(int32_t deviceId, int32_t axis) {
        Device* device = getDevice(deviceId);
        if (device) {
            device->relativeAxes.add(axis, true);
        }
    }

    void setKeyCodeState(int32_t deviceId, int32_t keyCode, int32_t state) {
        Device* device = getDevice(deviceId);
        if (device) {
            device->keyCodeStates.replaceValueFor(keyCode, state);
        }
    }

    void setScanCodeState(int32_t deviceId, int32_t scanCode, int32_t state) {
        Device* device = getDevice(deviceId);
        if (device) {
            device->scanCodeStates.replaceValueFor(scanCode, state);
        }
    }

    void setSwitchState(int32_t deviceId, int32_t switchCode, int32_t state) {
        Device* device = getDevice(deviceId);
        if (device) {
            device->switchStates.replaceValueFor(switchCode, state);
        }
    }

    void setAbsoluteAxisValue(int32_t deviceId, int32_t axis, int32_t value) {
        Device* device = getDevice(deviceId);
        if (device) {
            device->absoluteAxisValue.replaceValueFor(axis, value);
        }
    }

    void addKey(int32_t deviceId, int32_t scanCode, int32_t usageCode, int32_t keyCode,
                uint32_t flags) {
        Device* device = getDevice(deviceId);
        KeyInfo info;
        info.keyCode = keyCode;
        info.flags = flags;
        if (scanCode && device) {
            device->keysByScanCode.add(scanCode, info);
        }
        if (usageCode && device) {
            device->keysByUsageCode.add(usageCode, info);
        }
    }

    void addLed(int32_t deviceId, int32_t led, bool initialState) {
        Device* device = getDevice(deviceId);

        if (device) {
            device->leds.add(led, initialState);
        }
    }

    bool getLedState(int32_t deviceId, int32_t led) {
        Device* device = getDevice(deviceId);

        if (device) {
            return device->leds.valueFor(led);
        }
        return false;
    }

    std::vector<std::string>& getExcludedDevices() { return mExcludedDevices; }

    void addVirtualKeyDefinition(int32_t deviceId, const VirtualKeyDefinition& definition) {
        Device* device = getDevice(deviceId);

        if (device) {
            device->virtualKeys.push_back(definition);
        }
    }

    void enqueueEvent(nsecs_t when, int32_t deviceId, int32_t type, int32_t code, int32_t value) {
        RawEvent event;
        event.when = when;
        event.deviceId = deviceId;
        event.type = type;
        event.code = code;
        event.value = value;
        mEvents.push_back(event);

        if (type == EV_ABS) {
            setAbsoluteAxisValue(deviceId, code, value);
        }
    }

    void setVideoFrames(
            std::unordered_map<int32_t /*deviceId*/, std::vector<TouchVideoFrame>> videoFrames) {
        mVideoFrames = std::move(videoFrames);
    }

    void assertQueueIsEmpty() {}

private:
    Device* getDevice(int32_t deviceId) const {
        return (mDevices.find(deviceId) != mDevices.end()) ? mDevices.at(deviceId) : nullptr;
    }

    virtual uint32_t getDeviceClasses(int32_t deviceId) const {
        Device* device = getDevice(deviceId);
        return device ? device->classes : 0;
    }

    virtual InputDeviceIdentifier getDeviceIdentifier(int32_t deviceId) const {
        Device* device = getDevice(deviceId);
        return device ? device->identifier : InputDeviceIdentifier();
    }

    virtual int32_t getDeviceControllerNumber(int32_t) const { return 0; }

    virtual void getConfiguration(int32_t deviceId, PropertyMap* outConfiguration) const {
        Device* device = getDevice(deviceId);
        if (device) {
            *outConfiguration = device->configuration;
        }
    }

    virtual status_t getAbsoluteAxisInfo(int32_t deviceId, int axis,
                                         RawAbsoluteAxisInfo* outAxisInfo) const {
        Device* device = getDevice(deviceId);
        if (device) {
            ssize_t index = device->absoluteAxes.indexOfKey(axis);
            if (index >= 0) {
                *outAxisInfo = device->absoluteAxes.valueAt(index);
                return OK;
            }
        }
        outAxisInfo->clear();
        return -1;
    }

    virtual bool hasRelativeAxis(int32_t deviceId, int axis) const {
        Device* device = getDevice(deviceId);
        if (device) {
            return device->relativeAxes.indexOfKey(axis) >= 0;
        }
        return false;
    }

    virtual bool hasInputProperty(int32_t, int) const { return false; }

    virtual status_t mapKey(int32_t deviceId, int32_t scanCode, int32_t usageCode,
                            int32_t metaState, int32_t* outKeycode, int32_t* outMetaState,
                            uint32_t* outFlags) const {
        Device* device = getDevice(deviceId);
        if (device) {
            const KeyInfo* key = getKey(device, scanCode, usageCode);
            if (key) {
                if (outKeycode) {
                    *outKeycode = key->keyCode;
                }
                if (outFlags) {
                    *outFlags = key->flags;
                }
                if (outMetaState) {
                    *outMetaState = metaState;
                }
                return OK;
            }
        }
        return NAME_NOT_FOUND;
    }

    const KeyInfo* getKey(Device* device, int32_t scanCode, int32_t usageCode) const {
        if (usageCode) {
            ssize_t index = device->keysByUsageCode.indexOfKey(usageCode);
            if (index >= 0) {
                return &device->keysByUsageCode.valueAt(index);
            }
        }
        if (scanCode) {
            ssize_t index = device->keysByScanCode.indexOfKey(scanCode);
            if (index >= 0) {
                return &device->keysByScanCode.valueAt(index);
            }
        }
        return nullptr;
    }

    virtual status_t mapAxis(int32_t, int32_t, AxisInfo*) const { return NAME_NOT_FOUND; }

    virtual void setExcludedDevices(const std::vector<std::string>& devices) {
        mExcludedDevices = devices;
    }

    virtual size_t getEvents(int, RawEvent* buffer, size_t) {
        if (mEvents.empty()) {
            return 0;
        }

        *buffer = *mEvents.begin();
        mEvents.erase(mEvents.begin());
        return 1;
    }

    virtual std::vector<TouchVideoFrame> getVideoFrames(int32_t deviceId) {
        auto it = mVideoFrames.find(deviceId);
        if (it != mVideoFrames.end()) {
            std::vector<TouchVideoFrame> frames = std::move(it->second);
            mVideoFrames.erase(deviceId);
            return frames;
        }
        return {};
    }

    virtual int32_t getScanCodeState(int32_t deviceId, int32_t scanCode) const {
        Device* device = getDevice(deviceId);
        if (device) {
            ssize_t index = device->scanCodeStates.indexOfKey(scanCode);
            if (index >= 0) {
                return device->scanCodeStates.valueAt(index);
            }
        }
        return AKEY_STATE_UNKNOWN;
    }

    virtual int32_t getKeyCodeState(int32_t deviceId, int32_t keyCode) const {
        Device* device = getDevice(deviceId);
        if (device) {
            ssize_t index = device->keyCodeStates.indexOfKey(keyCode);
            if (index >= 0) {
                return device->keyCodeStates.valueAt(index);
            }
        }
        return AKEY_STATE_UNKNOWN;
    }

    virtual int32_t getSwitchState(int32_t deviceId, int32_t sw) const {
        Device* device = getDevice(deviceId);
        if (device) {
            ssize_t index = device->switchStates.indexOfKey(sw);
            if (index >= 0) {
                return device->switchStates.valueAt(index);
            }
        }
        return AKEY_STATE_UNKNOWN;
    }

    virtual status_t getAbsoluteAxisValue(int32_t deviceId, int32_t axis, int32_t* outValue) const {
        Device* device = getDevice(deviceId);
        if (device) {
            ssize_t index = device->absoluteAxisValue.indexOfKey(axis);
            if (index >= 0) {
                *outValue = device->absoluteAxisValue.valueAt(index);
                return OK;
            }
        }
        *outValue = 0;
        return -1;
    }

    virtual bool markSupportedKeyCodes(int32_t deviceId, size_t numCodes, const int32_t* keyCodes,
                                       uint8_t* outFlags) const {
        bool result = false;
        Device* device = getDevice(deviceId);
        if (device) {
            for (size_t i = 0; i < numCodes; i++) {
                for (size_t j = 0; j < device->keysByScanCode.size(); j++) {
                    if (keyCodes[i] == device->keysByScanCode.valueAt(j).keyCode) {
                        outFlags[i] = 1;
                        result = true;
                    }
                }
                for (size_t j = 0; j < device->keysByUsageCode.size(); j++) {
                    if (keyCodes[i] == device->keysByUsageCode.valueAt(j).keyCode) {
                        outFlags[i] = 1;
                        result = true;
                    }
                }
            }
        }
        return result;
    }

    virtual bool hasScanCode(int32_t deviceId, int32_t scanCode) const {
        Device* device = getDevice(deviceId);
        if (device) {
            ssize_t index = device->keysByScanCode.indexOfKey(scanCode);
            return index >= 0;
        }
        return false;
    }

    virtual bool hasLed(int32_t deviceId, int32_t led) const {
        Device* device = getDevice(deviceId);
        return device && device->leds.indexOfKey(led) >= 0;
    }

    virtual void setLedState(int32_t deviceId, int32_t led, bool on) {
        Device* device = getDevice(deviceId);
        if (device) {
            ssize_t index = device->leds.indexOfKey(led);
            if (index >= 0) {
                device->leds.replaceValueAt(led, on);
            }
        }
    }

    virtual void getVirtualKeyDefinitions(int32_t deviceId,
                                          std::vector<VirtualKeyDefinition>& outVirtualKeys) const {
        outVirtualKeys.clear();

        Device* device = getDevice(deviceId);
        if (device) {
            outVirtualKeys = device->virtualKeys;
        }
    }

    virtual sp<KeyCharacterMap> getKeyCharacterMap(int32_t) const { return nullptr; }

    virtual bool setKeyboardLayoutOverlay(int32_t, const sp<KeyCharacterMap>&) { return false; }

    virtual void vibrate(int32_t, nsecs_t) {}

    virtual void cancelVibrate(int32_t) {}

    virtual bool isExternal(int32_t) const { return false; }

    virtual void dump(std::string&) {}

    virtual void monitor() {}

    virtual void requestReopenDevices() {}

    virtual void wake() {}
};
// --- FakeInputReaderContext ---
class FakeInputReaderContext : public InputReaderContext {
    sp<EventHubInterface> mEventHub;
    sp<InputReaderPolicyInterface> mPolicy;
    sp<InputListenerInterface> mListener;
    int32_t mGlobalMetaState;
    bool mUpdateGlobalMetaStateWasCalled;
    int32_t mGeneration;
    uint32_t mNextSequenceNum;

public:
    FakeInputReaderContext(const sp<EventHubInterface>& eventHub,
                           const sp<InputReaderPolicyInterface>& policy,
                           const sp<InputListenerInterface>& listener)
          : mEventHub(eventHub),
            mPolicy(policy),
            mListener(listener),
            mGlobalMetaState(0),
            mNextSequenceNum(1) {}

    virtual ~FakeInputReaderContext() {}

    void assertUpdateGlobalMetaStateWasCalled() { mUpdateGlobalMetaStateWasCalled = false; }

    void setGlobalMetaState(int32_t state) { mGlobalMetaState = state; }

    uint32_t getGeneration() { return mGeneration; }

private:
    virtual void updateGlobalMetaState() { mUpdateGlobalMetaStateWasCalled = true; }

    virtual int32_t getGlobalMetaState() { return mGlobalMetaState; }

    virtual EventHubInterface* getEventHub() { return mEventHub.get(); }

    virtual InputReaderPolicyInterface* getPolicy() { return mPolicy.get(); }

    virtual InputListenerInterface* getListener() { return mListener.get(); }

    virtual void disableVirtualKeysUntil(nsecs_t) {}

    virtual bool shouldDropVirtualKey(nsecs_t, InputDevice*, int32_t, int32_t) { return false; }

    virtual void fadePointer() {}

    virtual void requestTimeoutAtTime(nsecs_t) {}

    virtual int32_t bumpGeneration() { return ++mGeneration; }

    virtual void getExternalStylusDevices(std::vector<InputDeviceInfo>& outDevices) {}

    virtual void dispatchExternalStylusState(const StylusState&) {}

    virtual uint32_t getNextSequenceNum() { return mNextSequenceNum++; }
};

// --- FakeInputMapper ---
class FakeInputMapper : public InputMapper {
    uint32_t mSources;
    int32_t mKeyboardType;
    int32_t mMetaState;
    KeyedVector<int32_t, int32_t> mKeyCodeStates;
    KeyedVector<int32_t, int32_t> mScanCodeStates;
    KeyedVector<int32_t, int32_t> mSwitchStates;
    std::vector<int32_t> mSupportedKeyCodes;
    RawEvent mLastEvent;

    bool mConfigureWasCalled;
    bool mResetWasCalled;
    bool mProcessWasCalled;

    std::optional<DisplayViewport> mViewport;

public:
    FakeInputMapper(InputDevice* device, uint32_t sources)
          : InputMapper(device),
            mSources(sources),
            mKeyboardType(AINPUT_KEYBOARD_TYPE_NONE),
            mMetaState(0),
            mConfigureWasCalled(false),
            mResetWasCalled(false),
            mProcessWasCalled(false) {}

    virtual ~FakeInputMapper() {}

    void setKeyboardType(int32_t keyboardType) { mKeyboardType = keyboardType; }

    void setMetaState(int32_t metaState) { mMetaState = metaState; }

    void assertConfigureWasCalled() { mConfigureWasCalled = false; }

    void assertResetWasCalled() { mResetWasCalled = false; }

    void assertProcessWasCalled(RawEvent* outLastEvent = nullptr) {
        if (outLastEvent) {
            *outLastEvent = mLastEvent;
        }
        mProcessWasCalled = false;
    }

    void setKeyCodeState(int32_t keyCode, int32_t state) {
        mKeyCodeStates.replaceValueFor(keyCode, state);
    }

    void setScanCodeState(int32_t scanCode, int32_t state) {
        mScanCodeStates.replaceValueFor(scanCode, state);
    }

    void setSwitchState(int32_t switchCode, int32_t state) {
        mSwitchStates.replaceValueFor(switchCode, state);
    }

    void addSupportedKeyCode(int32_t keyCode) { mSupportedKeyCodes.push_back(keyCode); }

private:
    virtual uint32_t getSources() { return mSources; }

    virtual void populateDeviceInfo(InputDeviceInfo* deviceInfo) {
        InputMapper::populateDeviceInfo(deviceInfo);

        if (mKeyboardType != AINPUT_KEYBOARD_TYPE_NONE) {
            deviceInfo->setKeyboardType(mKeyboardType);
        }
    }

    virtual void configure(nsecs_t, const InputReaderConfiguration* config, uint32_t changes) {
        mConfigureWasCalled = true;

        // Find the associated viewport if exist.
        const std::optional<uint8_t> displayPort = mDevice->getAssociatedDisplayPort();
        if (displayPort && (changes & InputReaderConfiguration::CHANGE_DISPLAY_INFO)) {
            mViewport = config->getDisplayViewportByPort(*displayPort);
        }
    }

    virtual void reset(nsecs_t) { mResetWasCalled = true; }

    virtual void process(const RawEvent* rawEvent) {
        mLastEvent = *rawEvent;
        mProcessWasCalled = true;
    }

    virtual int32_t getKeyCodeState(uint32_t, int32_t keyCode) {
        ssize_t index = mKeyCodeStates.indexOfKey(keyCode);
        return index >= 0 ? mKeyCodeStates.valueAt(index) : AKEY_STATE_UNKNOWN;
    }

    virtual int32_t getScanCodeState(uint32_t, int32_t scanCode) {
        ssize_t index = mScanCodeStates.indexOfKey(scanCode);
        return index >= 0 ? mScanCodeStates.valueAt(index) : AKEY_STATE_UNKNOWN;
    }

    virtual int32_t getSwitchState(uint32_t, int32_t switchCode) {
        ssize_t index = mSwitchStates.indexOfKey(switchCode);
        return index >= 0 ? mSwitchStates.valueAt(index) : AKEY_STATE_UNKNOWN;
    }

    virtual bool markSupportedKeyCodes(uint32_t, size_t numCodes, const int32_t* keyCodes,
                                       uint8_t* outFlags) {
        bool result = false;
        for (size_t i = 0; i < numCodes; i++) {
            for (size_t j = 0; j < mSupportedKeyCodes.size(); j++) {
                if (keyCodes[i] == mSupportedKeyCodes[j]) {
                    outFlags[i] = 1;
                    result = true;
                }
            }
        }
        return result;
    }

    virtual int32_t getMetaState() { return mMetaState; }

    virtual void fadePointer() {}

    virtual std::optional<int32_t> getAssociatedDisplay() {
        if (mViewport) {
            return std::make_optional(mViewport->displayId);
        }
        return std::nullopt;
    }
};
// --- InstrumentedInputReader ---
class InstrumentedInputReader : public InputReader {
    InputDevice* mNextDevice;

public:
    InstrumentedInputReader(const sp<EventHubInterface>& eventHub,
                            const sp<InputReaderPolicyInterface>& policy,
                            const sp<InputListenerInterface>& listener)
          : InputReader(eventHub, policy, listener), mNextDevice(nullptr) {}

    virtual ~InstrumentedInputReader() {}

    void setNextDevice(InputDevice* device) { mNextDevice = device; }

    InputDevice* newDevice(int32_t deviceId, int32_t controllerNumber, const std::string& name,
                           uint32_t classes, const std::string& location = "") {
        InputDeviceIdentifier identifier;
        identifier.name = name;
        identifier.location = location;
        int32_t generation = deviceId + 1;
        return new InputDevice(&mContext, deviceId, generation, controllerNumber, identifier,
                               classes);
    }

protected:
    virtual InputDevice* createDeviceLocked(int32_t deviceId, int32_t controllerNumber,
                                            const InputDeviceIdentifier& identifier,
                                            uint32_t classes) {
        if (mNextDevice) {
            InputDevice* device = mNextDevice;
            mNextDevice = nullptr;
            return device;
        }
        return InputReader::createDeviceLocked(deviceId, controllerNumber, identifier, classes);
    }

    friend class InputReaderTest;
};

} // namespace android

#endif // FUZZ_INPUTREADERHELPERS_H
