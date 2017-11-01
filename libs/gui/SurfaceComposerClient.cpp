/*
 * Copyright (C) 2007 The Android Open Source Project
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

#define LOG_TAG "SurfaceComposerClient"

#include <stdint.h>
#include <sys/types.h>

#include <utils/Errors.h>
#include <utils/Log.h>
#include <utils/Singleton.h>
#include <utils/SortedVector.h>
#include <utils/String8.h>
#include <utils/threads.h>

#include <binder/IServiceManager.h>

#include <system/graphics.h>

#include <ui/DisplayInfo.h>

#include <gui/BufferItemConsumer.h>
#include <gui/CpuConsumer.h>
#include <gui/IGraphicBufferProducer.h>
#include <gui/ISurfaceComposer.h>
#include <gui/ISurfaceComposerClient.h>
#include <gui/Surface.h>
#include <gui/SurfaceComposerClient.h>

#include <private/gui/ComposerService.h>
#include <private/gui/LayerState.h>

namespace android {
// ---------------------------------------------------------------------------

ANDROID_SINGLETON_STATIC_INSTANCE(ComposerService);

ComposerService::ComposerService()
: Singleton<ComposerService>() {
    Mutex::Autolock _l(mLock);
    connectLocked();
}

void ComposerService::connectLocked() {
    const String16 name("SurfaceFlinger");
    while (getService(name, &mComposerService) != NO_ERROR) {
        usleep(250000);
    }
    assert(mComposerService != NULL);

    // Create the death listener.
    class DeathObserver : public IBinder::DeathRecipient {
        ComposerService& mComposerService;
        virtual void binderDied(const wp<IBinder>& who) {
            ALOGW("ComposerService remote (surfaceflinger) died [%p]",
                  who.unsafe_get());
            mComposerService.composerServiceDied();
        }
     public:
        explicit DeathObserver(ComposerService& mgr) : mComposerService(mgr) { }
    };

    mDeathObserver = new DeathObserver(*const_cast<ComposerService*>(this));
    IInterface::asBinder(mComposerService)->linkToDeath(mDeathObserver);
}

/*static*/ sp<ISurfaceComposer> ComposerService::getComposerService() {
    ComposerService& instance = ComposerService::getInstance();
    Mutex::Autolock _l(instance.mLock);
    if (instance.mComposerService == NULL) {
        ComposerService::getInstance().connectLocked();
        assert(instance.mComposerService != NULL);
        ALOGD("ComposerService reconnected");
    }
    return instance.mComposerService;
}

void ComposerService::composerServiceDied()
{
    Mutex::Autolock _l(mLock);
    mComposerService = NULL;
    mDeathObserver = NULL;
}

// ---------------------------------------------------------------------------

static inline
int compare_type(const ComposerState& lhs, const ComposerState& rhs) {
    if (lhs.client < rhs.client)  return -1;
    if (lhs.client > rhs.client)  return 1;
    if (lhs.state.surface < rhs.state.surface)  return -1;
    if (lhs.state.surface > rhs.state.surface)  return 1;
    return 0;
}

static inline
int compare_type(const DisplayState& lhs, const DisplayState& rhs) {
    return compare_type(lhs.token, rhs.token);
}

class Composer : public Singleton<Composer>
{
    friend class Singleton<Composer>;

    mutable Mutex               mLock;
    SortedVector<ComposerState> mComposerStates;
    SortedVector<DisplayState > mDisplayStates;
    uint32_t                    mForceSynchronous;
    uint32_t                    mTransactionNestCount;
    bool                        mAnimation;

    Composer() : Singleton<Composer>(),
        mForceSynchronous(0), mTransactionNestCount(0),
        mAnimation(false)
    { }

    void openGlobalTransactionImpl();
    void closeGlobalTransactionImpl(bool synchronous);
    void setAnimationTransactionImpl();
    status_t enableVSyncInjectionsImpl(bool enable);
    status_t injectVSyncImpl(nsecs_t when);

    layer_state_t* getLayerStateLocked(
            const sp<SurfaceComposerClient>& client, const sp<IBinder>& id);

    DisplayState& getDisplayStateLocked(const sp<IBinder>& token);

public:
    sp<IBinder> createDisplay(const String8& displayName, bool secure);
    void destroyDisplay(const sp<IBinder>& display);
    sp<IBinder> getBuiltInDisplay(int32_t id);

    status_t setPosition(const sp<SurfaceComposerClient>& client, const sp<IBinder>& id,
            float x, float y);
    status_t setSize(const sp<SurfaceComposerClient>& client, const sp<IBinder>& id,
            uint32_t w, uint32_t h);
    status_t setLayer(const sp<SurfaceComposerClient>& client, const sp<IBinder>& id,
            int32_t z);
    status_t setRelativeLayer(const sp<SurfaceComposerClient>& client, const sp<IBinder>& id,
            const sp<IBinder>& relativeTo, int32_t z);
    status_t setFlags(const sp<SurfaceComposerClient>& client, const sp<IBinder>& id,
            uint32_t flags, uint32_t mask);
    status_t setTransparentRegionHint(
            const sp<SurfaceComposerClient>& client, const sp<IBinder>& id,
            const Region& transparentRegion);
    status_t setAlpha(const sp<SurfaceComposerClient>& client, const sp<IBinder>& id,
            float alpha);
    status_t setMatrix(const sp<SurfaceComposerClient>& client, const sp<IBinder>& id,
            float dsdx, float dtdx, float dtdy, float dsdy);
    status_t setOrientation(int orientation);
    status_t setCrop(const sp<SurfaceComposerClient>& client, const sp<IBinder>& id,
            const Rect& crop);
    status_t setFinalCrop(const sp<SurfaceComposerClient>& client,
            const sp<IBinder>& id, const Rect& crop);
    status_t setLayerStack(const sp<SurfaceComposerClient>& client,
            const sp<IBinder>& id, uint32_t layerStack);
    status_t deferTransactionUntil(const sp<SurfaceComposerClient>& client,
            const sp<IBinder>& id, const sp<IBinder>& handle,
            uint64_t frameNumber);
    status_t deferTransactionUntil(const sp<SurfaceComposerClient>& client,
            const sp<IBinder>& id, const sp<Surface>& barrierSurface,
            uint64_t frameNumber);
    status_t reparentChildren(const sp<SurfaceComposerClient>& client,
            const sp<IBinder>& id,
            const sp<IBinder>& newParentHandle);
    status_t detachChildren(const sp<SurfaceComposerClient>& client,
            const sp<IBinder>& id);
    status_t setOverrideScalingMode(const sp<SurfaceComposerClient>& client,
            const sp<IBinder>& id, int32_t overrideScalingMode);
    status_t setGeometryAppliesWithResize(const sp<SurfaceComposerClient>& client,
            const sp<IBinder>& id);

    status_t setDisplaySurface(const sp<IBinder>& token,
            sp<IGraphicBufferProducer> bufferProducer);
    void setDisplayLayerStack(const sp<IBinder>& token, uint32_t layerStack);
    void setDisplayProjection(const sp<IBinder>& token,
            uint32_t orientation,
            const Rect& layerStackRect,
            const Rect& displayRect);
    void setDisplaySize(const sp<IBinder>& token, uint32_t width, uint32_t height);

    static void setAnimationTransaction() {
        Composer::getInstance().setAnimationTransactionImpl();
    }

    static void openGlobalTransaction() {
        Composer::getInstance().openGlobalTransactionImpl();
    }

    static void closeGlobalTransaction(bool synchronous) {
        Composer::getInstance().closeGlobalTransactionImpl(synchronous);
    }

    static status_t enableVSyncInjections(bool enable) {
        return Composer::getInstance().enableVSyncInjectionsImpl(enable);
    }

    static status_t injectVSync(nsecs_t when) {
        return Composer::getInstance().injectVSyncImpl(when);
    }
};

ANDROID_SINGLETON_STATIC_INSTANCE(Composer);

// ---------------------------------------------------------------------------

sp<IBinder> Composer::createDisplay(const String8& displayName, bool secure) {
    return ComposerService::getComposerService()->createDisplay(displayName,
            secure);
}

void Composer::destroyDisplay(const sp<IBinder>& display) {
    return ComposerService::getComposerService()->destroyDisplay(display);
}

sp<IBinder> Composer::getBuiltInDisplay(int32_t id) {
    return ComposerService::getComposerService()->getBuiltInDisplay(id);
}

void Composer::openGlobalTransactionImpl() {
    { // scope for the lock
        Mutex::Autolock _l(mLock);
        mTransactionNestCount += 1;
    }
}

void Composer::closeGlobalTransactionImpl(bool synchronous) {
    sp<ISurfaceComposer> sm(ComposerService::getComposerService());

    Vector<ComposerState> transaction;
    Vector<DisplayState> displayTransaction;
    uint32_t flags = 0;

    { // scope for the lock
        Mutex::Autolock _l(mLock);
        mForceSynchronous |= synchronous;
        if (!mTransactionNestCount) {
            ALOGW("At least one call to closeGlobalTransaction() was not matched by a prior "
                    "call to openGlobalTransaction().");
        } else if (--mTransactionNestCount) {
            return;
        }

        transaction = mComposerStates;
        mComposerStates.clear();

        displayTransaction = mDisplayStates;
        mDisplayStates.clear();

        if (mForceSynchronous) {
            flags |= ISurfaceComposer::eSynchronous;
        }
        if (mAnimation) {
            flags |= ISurfaceComposer::eAnimation;
        }

        mForceSynchronous = false;
        mAnimation = false;
    }

   sm->setTransactionState(transaction, displayTransaction, flags);
}

status_t Composer::enableVSyncInjectionsImpl(bool enable) {
    sp<ISurfaceComposer> sm(ComposerService::getComposerService());
    return sm->enableVSyncInjections(enable);
}

status_t Composer::injectVSyncImpl(nsecs_t when) {
    sp<ISurfaceComposer> sm(ComposerService::getComposerService());
    return sm->injectVSync(when);
}

void Composer::setAnimationTransactionImpl() {
    Mutex::Autolock _l(mLock);
    mAnimation = true;
}

layer_state_t* Composer::getLayerStateLocked(
        const sp<SurfaceComposerClient>& client, const sp<IBinder>& id) {

    ComposerState s;
    s.client = client->mClient;
    s.state.surface = id;

    ssize_t index = mComposerStates.indexOf(s);
    if (index < 0) {
        // we don't have it, add an initialized layer_state to our list
        index = mComposerStates.add(s);
    }

    ComposerState* const out = mComposerStates.editArray();
    return &(out[index].state);
}

status_t Composer::setPosition(const sp<SurfaceComposerClient>& client,
        const sp<IBinder>& id, float x, float y) {
    Mutex::Autolock _l(mLock);
    layer_state_t* s = getLayerStateLocked(client, id);
    if (!s)
        return BAD_INDEX;
    s->what |= layer_state_t::ePositionChanged;
    s->x = x;
    s->y = y;
    return NO_ERROR;
}

status_t Composer::setSize(const sp<SurfaceComposerClient>& client,
        const sp<IBinder>& id, uint32_t w, uint32_t h) {
    Mutex::Autolock _l(mLock);
    layer_state_t* s = getLayerStateLocked(client, id);
    if (!s)
        return BAD_INDEX;
    s->what |= layer_state_t::eSizeChanged;
    s->w = w;
    s->h = h;

    // Resizing a surface makes the transaction synchronous.
    mForceSynchronous = true;

    return NO_ERROR;
}

status_t Composer::setLayer(const sp<SurfaceComposerClient>& client,
        const sp<IBinder>& id, int32_t z) {
    Mutex::Autolock _l(mLock);
    layer_state_t* s = getLayerStateLocked(client, id);
    if (!s)
        return BAD_INDEX;
    s->what |= layer_state_t::eLayerChanged;
    s->z = z;
    return NO_ERROR;
}

status_t Composer::setRelativeLayer(const sp<SurfaceComposerClient>& client,
        const sp<IBinder>& id, const sp<IBinder>& relativeTo,
        int32_t z) {
    Mutex::Autolock _l(mLock);
    layer_state_t* s = getLayerStateLocked(client, id);
    if (!s) {
        return BAD_INDEX;
    }
    s->what |= layer_state_t::eRelativeLayerChanged;
    s->relativeLayerHandle = relativeTo;
    s->z = z;
    return NO_ERROR;
}

status_t Composer::setFlags(const sp<SurfaceComposerClient>& client,
        const sp<IBinder>& id, uint32_t flags,
        uint32_t mask) {
    Mutex::Autolock _l(mLock);
    layer_state_t* s = getLayerStateLocked(client, id);
    if (!s)
        return BAD_INDEX;
    if ((mask & layer_state_t::eLayerOpaque) ||
            (mask & layer_state_t::eLayerHidden) ||
            (mask & layer_state_t::eLayerSecure)) {
        s->what |= layer_state_t::eFlagsChanged;
    }
    s->flags &= ~mask;
    s->flags |= (flags & mask);
    s->mask |= mask;
    return NO_ERROR;
}

status_t Composer::setTransparentRegionHint(
        const sp<SurfaceComposerClient>& client, const sp<IBinder>& id,
        const Region& transparentRegion) {
    Mutex::Autolock _l(mLock);
    layer_state_t* s = getLayerStateLocked(client, id);
    if (!s)
        return BAD_INDEX;
    s->what |= layer_state_t::eTransparentRegionChanged;
    s->transparentRegion = transparentRegion;
    return NO_ERROR;
}

status_t Composer::setAlpha(const sp<SurfaceComposerClient>& client,
        const sp<IBinder>& id, float alpha) {
    Mutex::Autolock _l(mLock);
    layer_state_t* s = getLayerStateLocked(client, id);
    if (!s)
        return BAD_INDEX;
    s->what |= layer_state_t::eAlphaChanged;
    s->alpha = alpha;
    return NO_ERROR;
}

status_t Composer::setLayerStack(const sp<SurfaceComposerClient>& client,
        const sp<IBinder>& id, uint32_t layerStack) {
    Mutex::Autolock _l(mLock);
    layer_state_t* s = getLayerStateLocked(client, id);
    if (!s)
        return BAD_INDEX;
    s->what |= layer_state_t::eLayerStackChanged;
    s->layerStack = layerStack;
    return NO_ERROR;
}

status_t Composer::setMatrix(const sp<SurfaceComposerClient>& client,
        const sp<IBinder>& id, float dsdx, float dtdx,
        float dtdy, float dsdy) {
    Mutex::Autolock _l(mLock);
    layer_state_t* s = getLayerStateLocked(client, id);
    if (!s)
        return BAD_INDEX;
    s->what |= layer_state_t::eMatrixChanged;
    layer_state_t::matrix22_t matrix;
    matrix.dsdx = dsdx;
    matrix.dtdx = dtdx;
    matrix.dsdy = dsdy;
    matrix.dtdy = dtdy;
    s->matrix = matrix;
    return NO_ERROR;
}

status_t Composer::setCrop(const sp<SurfaceComposerClient>& client,
        const sp<IBinder>& id, const Rect& crop) {
    Mutex::Autolock _l(mLock);
    layer_state_t* s = getLayerStateLocked(client, id);
    if (!s)
        return BAD_INDEX;
    s->what |= layer_state_t::eCropChanged;
    s->crop = crop;
    return NO_ERROR;
}

status_t Composer::setFinalCrop(const sp<SurfaceComposerClient>& client,
        const sp<IBinder>& id, const Rect& crop) {
    Mutex::Autolock _l(mLock);
    layer_state_t* s = getLayerStateLocked(client, id);
    if (!s) {
        return BAD_INDEX;
    }
    s->what |= layer_state_t::eFinalCropChanged;
    s->finalCrop = crop;
    return NO_ERROR;
}

status_t Composer::deferTransactionUntil(
        const sp<SurfaceComposerClient>& client, const sp<IBinder>& id,
        const sp<IBinder>& handle, uint64_t frameNumber) {
    Mutex::Autolock lock(mLock);
    layer_state_t* s = getLayerStateLocked(client, id);
    if (!s) {
        return BAD_INDEX;
    }
    s->what |= layer_state_t::eDeferTransaction;
    s->barrierHandle = handle;
    s->frameNumber = frameNumber;
    return NO_ERROR;
}

status_t Composer::deferTransactionUntil(
        const sp<SurfaceComposerClient>& client, const sp<IBinder>& id,
        const sp<Surface>& barrierSurface, uint64_t frameNumber) {
    Mutex::Autolock lock(mLock);
    layer_state_t* s = getLayerStateLocked(client, id);
    if (!s) {
        return BAD_INDEX;
    }
    s->what |= layer_state_t::eDeferTransaction;
    s->barrierGbp = barrierSurface->getIGraphicBufferProducer();
    s->frameNumber = frameNumber;
    return NO_ERROR;
}

status_t Composer::reparentChildren(
        const sp<SurfaceComposerClient>& client,
        const sp<IBinder>& id,
        const sp<IBinder>& newParentHandle) {
    Mutex::Autolock lock(mLock);
    layer_state_t* s = getLayerStateLocked(client, id);
    if (!s) {
        return BAD_INDEX;
    }
    s->what |= layer_state_t::eReparentChildren;
    s->reparentHandle = newParentHandle;
    return NO_ERROR;
}

status_t Composer::detachChildren(
        const sp<SurfaceComposerClient>& client,
        const sp<IBinder>& id) {
    Mutex::Autolock lock(mLock);
    layer_state_t* s = getLayerStateLocked(client, id);
    if (!s) {
        return BAD_INDEX;
    }
    s->what |= layer_state_t::eDetachChildren;
    return NO_ERROR;
}

status_t Composer::setOverrideScalingMode(
        const sp<SurfaceComposerClient>& client,
        const sp<IBinder>& id, int32_t overrideScalingMode) {
    Mutex::Autolock lock(mLock);
    layer_state_t* s = getLayerStateLocked(client, id);
    if (!s) {
        return BAD_INDEX;
    }

    switch (overrideScalingMode) {
        case NATIVE_WINDOW_SCALING_MODE_FREEZE:
        case NATIVE_WINDOW_SCALING_MODE_SCALE_TO_WINDOW:
        case NATIVE_WINDOW_SCALING_MODE_SCALE_CROP:
        case NATIVE_WINDOW_SCALING_MODE_NO_SCALE_CROP:
        case -1:
            break;
        default:
            ALOGE("unknown scaling mode: %d",
                    overrideScalingMode);
            return BAD_VALUE;
    }

    s->what |= layer_state_t::eOverrideScalingModeChanged;
    s->overrideScalingMode = overrideScalingMode;
    return NO_ERROR;
}

status_t Composer::setGeometryAppliesWithResize(
        const sp<SurfaceComposerClient>& client,
        const sp<IBinder>& id) {
    Mutex::Autolock lock(mLock);
    layer_state_t* s = getLayerStateLocked(client, id);
    if (!s) {
        return BAD_INDEX;
    }
    s->what |= layer_state_t::eGeometryAppliesWithResize;
    return NO_ERROR;
}

// ---------------------------------------------------------------------------

DisplayState& Composer::getDisplayStateLocked(const sp<IBinder>& token) {
    DisplayState s;
    s.token = token;
    ssize_t index = mDisplayStates.indexOf(s);
    if (index < 0) {
        // we don't have it, add an initialized layer_state to our list
        s.what = 0;
        index = mDisplayStates.add(s);
    }
    return mDisplayStates.editItemAt(static_cast<size_t>(index));
}

status_t Composer::setDisplaySurface(const sp<IBinder>& token,
        sp<IGraphicBufferProducer> bufferProducer) {
    if (bufferProducer.get() != nullptr) {
        // Make sure that composition can never be stalled by a virtual display
        // consumer that isn't processing buffers fast enough.
        status_t err = bufferProducer->setAsyncMode(true);
        if (err != NO_ERROR) {
            ALOGE("Composer::setDisplaySurface Failed to enable async mode on the "
                    "BufferQueue. This BufferQueue cannot be used for virtual "
                    "display. (%d)", err);
            return err;
        }
    }
    Mutex::Autolock _l(mLock);
    DisplayState& s(getDisplayStateLocked(token));
    s.surface = bufferProducer;
    s.what |= DisplayState::eSurfaceChanged;
    return NO_ERROR;
}

void Composer::setDisplayLayerStack(const sp<IBinder>& token,
        uint32_t layerStack) {
    Mutex::Autolock _l(mLock);
    DisplayState& s(getDisplayStateLocked(token));
    s.layerStack = layerStack;
    s.what |= DisplayState::eLayerStackChanged;
}

void Composer::setDisplayProjection(const sp<IBinder>& token,
        uint32_t orientation,
        const Rect& layerStackRect,
        const Rect& displayRect) {
    Mutex::Autolock _l(mLock);
    DisplayState& s(getDisplayStateLocked(token));
    s.orientation = orientation;
    s.viewport = layerStackRect;
    s.frame = displayRect;
    s.what |= DisplayState::eDisplayProjectionChanged;
    mForceSynchronous = true; // TODO: do we actually still need this?
}

void Composer::setDisplaySize(const sp<IBinder>& token, uint32_t width, uint32_t height) {
    Mutex::Autolock _l(mLock);
    DisplayState& s(getDisplayStateLocked(token));
    s.width = width;
    s.height = height;
    s.what |= DisplayState::eDisplaySizeChanged;
}

// ---------------------------------------------------------------------------

SurfaceComposerClient::SurfaceComposerClient()
    : mStatus(NO_INIT), mComposer(Composer::getInstance())
{
}

SurfaceComposerClient::SurfaceComposerClient(const sp<IGraphicBufferProducer>& root)
    : mStatus(NO_INIT), mComposer(Composer::getInstance()), mParent(root)
{
}

void SurfaceComposerClient::onFirstRef() {
    sp<ISurfaceComposer> sm(ComposerService::getComposerService());
    if (sm != 0) {
        auto rootProducer = mParent.promote();
        sp<ISurfaceComposerClient> conn;
        conn = (rootProducer != nullptr) ? sm->createScopedConnection(rootProducer) :
                sm->createConnection();
        if (conn != 0) {
            mClient = conn;
            mStatus = NO_ERROR;
        }
    }
}

SurfaceComposerClient::~SurfaceComposerClient() {
    dispose();
}

status_t SurfaceComposerClient::initCheck() const {
    return mStatus;
}

sp<IBinder> SurfaceComposerClient::connection() const {
    return IInterface::asBinder(mClient);
}

status_t SurfaceComposerClient::linkToComposerDeath(
        const sp<IBinder::DeathRecipient>& recipient,
        void* cookie, uint32_t flags) {
    sp<ISurfaceComposer> sm(ComposerService::getComposerService());
    return IInterface::asBinder(sm)->linkToDeath(recipient, cookie, flags);
}

void SurfaceComposerClient::dispose() {
    // this can be called more than once.
    sp<ISurfaceComposerClient> client;
    Mutex::Autolock _lm(mLock);
    if (mClient != 0) {
        client = mClient; // hold ref while lock is held
        mClient.clear();
    }
    mStatus = NO_INIT;
}

sp<SurfaceControl> SurfaceComposerClient::createSurface(
        const String8& name,
        uint32_t w,
        uint32_t h,
        PixelFormat format,
        uint32_t flags,
        SurfaceControl* parent,
        uint32_t windowType,
        uint32_t ownerUid)
{
    sp<SurfaceControl> sur;
    if (mStatus == NO_ERROR) {
        sp<IBinder> handle;
        sp<IBinder> parentHandle;
        sp<IGraphicBufferProducer> gbp;

        if (parent != nullptr) {
            parentHandle = parent->getHandle();
        }
        status_t err = mClient->createSurface(name, w, h, format, flags, parentHandle,
                windowType, ownerUid, &handle, &gbp);
        ALOGE_IF(err, "SurfaceComposerClient::createSurface error %s", strerror(-err));
        if (err == NO_ERROR) {
            sur = new SurfaceControl(this, handle, gbp);
        }
    }
    return sur;
}

sp<IBinder> SurfaceComposerClient::createDisplay(const String8& displayName,
        bool secure) {
    return Composer::getInstance().createDisplay(displayName, secure);
}

void SurfaceComposerClient::destroyDisplay(const sp<IBinder>& display) {
    Composer::getInstance().destroyDisplay(display);
}

sp<IBinder> SurfaceComposerClient::getBuiltInDisplay(int32_t id) {
    return Composer::getInstance().getBuiltInDisplay(id);
}

status_t SurfaceComposerClient::destroySurface(const sp<IBinder>& sid) {
    if (mStatus != NO_ERROR)
        return mStatus;
    status_t err = mClient->destroySurface(sid);
    return err;
}

status_t SurfaceComposerClient::clearLayerFrameStats(const sp<IBinder>& token) const {
    if (mStatus != NO_ERROR) {
        return mStatus;
    }
    return mClient->clearLayerFrameStats(token);
}

status_t SurfaceComposerClient::getLayerFrameStats(const sp<IBinder>& token,
        FrameStats* outStats) const {
    if (mStatus != NO_ERROR) {
        return mStatus;
    }
    return mClient->getLayerFrameStats(token, outStats);
}

inline Composer& SurfaceComposerClient::getComposer() {
    return mComposer;
}

// ----------------------------------------------------------------------------

void SurfaceComposerClient::openGlobalTransaction() {
    Composer::openGlobalTransaction();
}

void SurfaceComposerClient::closeGlobalTransaction(bool synchronous) {
    Composer::closeGlobalTransaction(synchronous);
}

void SurfaceComposerClient::setAnimationTransaction() {
    Composer::setAnimationTransaction();
}

status_t SurfaceComposerClient::enableVSyncInjections(bool enable) {
    return Composer::enableVSyncInjections(enable);
}

status_t SurfaceComposerClient::injectVSync(nsecs_t when) {
    return Composer::injectVSync(when);
}

// ----------------------------------------------------------------------------

status_t SurfaceComposerClient::setCrop(const sp<IBinder>& id, const Rect& crop) {
    return getComposer().setCrop(this, id, crop);
}

status_t SurfaceComposerClient::setFinalCrop(const sp<IBinder>& id,
        const Rect& crop) {
    return getComposer().setFinalCrop(this, id, crop);
}

status_t SurfaceComposerClient::setPosition(const sp<IBinder>& id, float x, float y) {
    return getComposer().setPosition(this, id, x, y);
}

status_t SurfaceComposerClient::setSize(const sp<IBinder>& id, uint32_t w, uint32_t h) {
    return getComposer().setSize(this, id, w, h);
}

status_t SurfaceComposerClient::setLayer(const sp<IBinder>& id, int32_t z) {
    return getComposer().setLayer(this, id, z);
}

status_t SurfaceComposerClient::setRelativeLayer(const sp<IBinder>& id,
        const sp<IBinder>& relativeTo, int32_t z) {
    return getComposer().setRelativeLayer(this, id, relativeTo, z);
}

status_t SurfaceComposerClient::hide(const sp<IBinder>& id) {
    return getComposer().setFlags(this, id,
            layer_state_t::eLayerHidden,
            layer_state_t::eLayerHidden);
}

status_t SurfaceComposerClient::show(const sp<IBinder>& id) {
    return getComposer().setFlags(this, id,
            0,
            layer_state_t::eLayerHidden);
}

status_t SurfaceComposerClient::setFlags(const sp<IBinder>& id, uint32_t flags,
        uint32_t mask) {
    return getComposer().setFlags(this, id, flags, mask);
}

status_t SurfaceComposerClient::setTransparentRegionHint(const sp<IBinder>& id,
        const Region& transparentRegion) {
    return getComposer().setTransparentRegionHint(this, id, transparentRegion);
}

status_t SurfaceComposerClient::setAlpha(const sp<IBinder>& id, float alpha) {
    return getComposer().setAlpha(this, id, alpha);
}

status_t SurfaceComposerClient::setLayerStack(const sp<IBinder>& id, uint32_t layerStack) {
    return getComposer().setLayerStack(this, id, layerStack);
}

status_t SurfaceComposerClient::setMatrix(const sp<IBinder>& id, float dsdx, float dtdx,
        float dtdy, float dsdy) {
    return getComposer().setMatrix(this, id, dsdx, dtdx, dtdy, dsdy);
}

status_t SurfaceComposerClient::deferTransactionUntil(const sp<IBinder>& id,
        const sp<IBinder>& handle, uint64_t frameNumber) {
    return getComposer().deferTransactionUntil(this, id, handle, frameNumber);
}

status_t SurfaceComposerClient::deferTransactionUntil(const sp<IBinder>& id,
        const sp<Surface>& barrierSurface, uint64_t frameNumber) {
    return getComposer().deferTransactionUntil(this, id, barrierSurface, frameNumber);
}

status_t SurfaceComposerClient::reparentChildren(const sp<IBinder>& id,
        const sp<IBinder>& newParentHandle) {
    return getComposer().reparentChildren(this, id, newParentHandle);
}

status_t SurfaceComposerClient::detachChildren(const sp<IBinder>& id) {
    return getComposer().detachChildren(this, id);
}

status_t SurfaceComposerClient::setOverrideScalingMode(
        const sp<IBinder>& id, int32_t overrideScalingMode) {
    return getComposer().setOverrideScalingMode(
            this, id, overrideScalingMode);
}

status_t SurfaceComposerClient::setGeometryAppliesWithResize(
        const sp<IBinder>& id) {
    return getComposer().setGeometryAppliesWithResize(this, id);
}

// ----------------------------------------------------------------------------

status_t SurfaceComposerClient::setDisplaySurface(const sp<IBinder>& token,
        sp<IGraphicBufferProducer> bufferProducer) {
    return Composer::getInstance().setDisplaySurface(token, bufferProducer);
}

void SurfaceComposerClient::setDisplayLayerStack(const sp<IBinder>& token,
        uint32_t layerStack) {
    Composer::getInstance().setDisplayLayerStack(token, layerStack);
}

void SurfaceComposerClient::setDisplayProjection(const sp<IBinder>& token,
        uint32_t orientation,
        const Rect& layerStackRect,
        const Rect& displayRect) {
    Composer::getInstance().setDisplayProjection(token, orientation,
            layerStackRect, displayRect);
}

void SurfaceComposerClient::setDisplaySize(const sp<IBinder>& token,
        uint32_t width, uint32_t height) {
    Composer::getInstance().setDisplaySize(token, width, height);
}

// ----------------------------------------------------------------------------

status_t SurfaceComposerClient::getDisplayConfigs(
        const sp<IBinder>& display, Vector<DisplayInfo>* configs)
{
    return ComposerService::getComposerService()->getDisplayConfigs(display, configs);
}

status_t SurfaceComposerClient::getDisplayInfo(const sp<IBinder>& display,
        DisplayInfo* info) {
    Vector<DisplayInfo> configs;
    status_t result = getDisplayConfigs(display, &configs);
    if (result != NO_ERROR) {
        return result;
    }

    int activeId = getActiveConfig(display);
    if (activeId < 0) {
        ALOGE("No active configuration found");
        return NAME_NOT_FOUND;
    }

    *info = configs[static_cast<size_t>(activeId)];
    return NO_ERROR;
}

int SurfaceComposerClient::getActiveConfig(const sp<IBinder>& display) {
    return ComposerService::getComposerService()->getActiveConfig(display);
}

status_t SurfaceComposerClient::setActiveConfig(const sp<IBinder>& display, int id) {
    return ComposerService::getComposerService()->setActiveConfig(display, id);
}

status_t SurfaceComposerClient::getDisplayColorModes(const sp<IBinder>& display,
        Vector<android_color_mode_t>* outColorModes) {
    return ComposerService::getComposerService()->getDisplayColorModes(display, outColorModes);
}

android_color_mode_t SurfaceComposerClient::getActiveColorMode(const sp<IBinder>& display) {
    return ComposerService::getComposerService()->getActiveColorMode(display);
}

status_t SurfaceComposerClient::setActiveColorMode(const sp<IBinder>& display,
        android_color_mode_t colorMode) {
    return ComposerService::getComposerService()->setActiveColorMode(display, colorMode);
}

void SurfaceComposerClient::setDisplayPowerMode(const sp<IBinder>& token,
        int mode) {
    ComposerService::getComposerService()->setPowerMode(token, mode);
}

status_t SurfaceComposerClient::clearAnimationFrameStats() {
    return ComposerService::getComposerService()->clearAnimationFrameStats();
}

status_t SurfaceComposerClient::getAnimationFrameStats(FrameStats* outStats) {
    return ComposerService::getComposerService()->getAnimationFrameStats(outStats);
}

status_t SurfaceComposerClient::getHdrCapabilities(const sp<IBinder>& display,
        HdrCapabilities* outCapabilities) {
    return ComposerService::getComposerService()->getHdrCapabilities(display,
            outCapabilities);
}

// ----------------------------------------------------------------------------

status_t ScreenshotClient::capture(
        const sp<IBinder>& display,
        const sp<IGraphicBufferProducer>& producer,
        Rect sourceCrop, uint32_t reqWidth, uint32_t reqHeight,
        int32_t minLayerZ, int32_t maxLayerZ, bool useIdentityTransform) {
    sp<ISurfaceComposer> s(ComposerService::getComposerService());
    if (s == NULL) return NO_INIT;
    return s->captureScreen(display, producer, sourceCrop,
            reqWidth, reqHeight, minLayerZ, maxLayerZ, useIdentityTransform);
}

status_t ScreenshotClient::captureToBuffer(const sp<IBinder>& display,
        Rect sourceCrop, uint32_t reqWidth, uint32_t reqHeight,
        int32_t minLayerZ, int32_t maxLayerZ, bool useIdentityTransform,
        uint32_t rotation,
        sp<GraphicBuffer>* outBuffer) {
    sp<ISurfaceComposer> s(ComposerService::getComposerService());
    if (s == NULL) return NO_INIT;

    sp<IGraphicBufferConsumer> gbpConsumer;
    sp<IGraphicBufferProducer> producer;
    BufferQueue::createBufferQueue(&producer, &gbpConsumer);
    sp<BufferItemConsumer> consumer(new BufferItemConsumer(gbpConsumer,
           GRALLOC_USAGE_HW_TEXTURE | GRALLOC_USAGE_SW_READ_NEVER | GRALLOC_USAGE_SW_WRITE_NEVER,
           1, true));

    status_t ret = s->captureScreen(display, producer, sourceCrop, reqWidth, reqHeight,
            minLayerZ, maxLayerZ, useIdentityTransform,
            static_cast<ISurfaceComposer::Rotation>(rotation));
    if (ret != NO_ERROR) {
        return ret;
    }
    BufferItem b;
    consumer->acquireBuffer(&b, 0, true);
    *outBuffer = b.mGraphicBuffer;
    return ret;
}

ScreenshotClient::ScreenshotClient()
    : mHaveBuffer(false) {
    memset(&mBuffer, 0, sizeof(mBuffer));
}

ScreenshotClient::~ScreenshotClient() {
    ScreenshotClient::release();
}

sp<CpuConsumer> ScreenshotClient::getCpuConsumer() const {
    if (mCpuConsumer == NULL) {
        sp<IGraphicBufferConsumer> consumer;
        BufferQueue::createBufferQueue(&mProducer, &consumer);
        mCpuConsumer = new CpuConsumer(consumer, 1);
        mCpuConsumer->setName(String8("ScreenshotClient"));
    }
    return mCpuConsumer;
}

status_t ScreenshotClient::update(const sp<IBinder>& display,
        Rect sourceCrop, uint32_t reqWidth, uint32_t reqHeight,
        int32_t minLayerZ, int32_t maxLayerZ,
        bool useIdentityTransform, uint32_t rotation) {
    sp<ISurfaceComposer> s(ComposerService::getComposerService());
    if (s == NULL) return NO_INIT;
    sp<CpuConsumer> cpuConsumer = getCpuConsumer();

    if (mHaveBuffer) {
        mCpuConsumer->unlockBuffer(mBuffer);
        memset(&mBuffer, 0, sizeof(mBuffer));
        mHaveBuffer = false;
    }

    status_t err = s->captureScreen(display, mProducer, sourceCrop,
            reqWidth, reqHeight, minLayerZ, maxLayerZ, useIdentityTransform,
            static_cast<ISurfaceComposer::Rotation>(rotation));

    if (err == NO_ERROR) {
        err = mCpuConsumer->lockNextBuffer(&mBuffer);
        if (err == NO_ERROR) {
            mHaveBuffer = true;
        }
    }
    return err;
}

status_t ScreenshotClient::update(const sp<IBinder>& display,
        Rect sourceCrop, uint32_t reqWidth, uint32_t reqHeight,
        int32_t minLayerZ, int32_t maxLayerZ,
        bool useIdentityTransform) {

    return ScreenshotClient::update(display, sourceCrop, reqWidth, reqHeight,
            minLayerZ, maxLayerZ, useIdentityTransform, ISurfaceComposer::eRotateNone);
}

status_t ScreenshotClient::update(const sp<IBinder>& display, Rect sourceCrop,
        bool useIdentityTransform) {
    return ScreenshotClient::update(display, sourceCrop, 0, 0,
            INT32_MIN, INT32_MAX,
            useIdentityTransform, ISurfaceComposer::eRotateNone);
}

status_t ScreenshotClient::update(const sp<IBinder>& display, Rect sourceCrop,
        uint32_t reqWidth, uint32_t reqHeight, bool useIdentityTransform) {
    return ScreenshotClient::update(display, sourceCrop, reqWidth, reqHeight,
            INT32_MIN, INT32_MAX,
            useIdentityTransform, ISurfaceComposer::eRotateNone);
}

void ScreenshotClient::release() {
    if (mHaveBuffer) {
        mCpuConsumer->unlockBuffer(mBuffer);
        memset(&mBuffer, 0, sizeof(mBuffer));
        mHaveBuffer = false;
    }
    mCpuConsumer.clear();
}

void const* ScreenshotClient::getPixels() const {
    return mBuffer.data;
}

uint32_t ScreenshotClient::getWidth() const {
    return mBuffer.width;
}

uint32_t ScreenshotClient::getHeight() const {
    return mBuffer.height;
}

PixelFormat ScreenshotClient::getFormat() const {
    return mBuffer.format;
}

uint32_t ScreenshotClient::getStride() const {
    return mBuffer.stride;
}

size_t ScreenshotClient::getSize() const {
    return mBuffer.stride * mBuffer.height * bytesPerPixel(mBuffer.format);
}

android_dataspace ScreenshotClient::getDataSpace() const {
    return mBuffer.dataSpace;
}

// ----------------------------------------------------------------------------
}; // namespace android
