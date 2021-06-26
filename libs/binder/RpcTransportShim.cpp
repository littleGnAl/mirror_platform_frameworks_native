/*
 * Copyright (C) 2021 The Android Open Source Project
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

#define LOG_TAG "RpcTransportShim"
#include <log/log.h>

#include "RpcTransportShim.h"

#include <dlfcn.h>

#include <memory>
#include <mutex>

#include "RpcTransportRaw.h"
#include "RpcTransportTls.h"

#define LOG_DLOPEN_DETAIL(...) ALOGI(__VA_ARGS__)

namespace android {

namespace {

using Dlhandle = std::shared_ptr<void>;

constexpr const char* kLibBinderTransport = "libbinder_tls.so";

// FIXME this leaks!

std::mutex gMutex;

void dlhandleDeleter(void* rawHandle) {
    std::lock_guard<std::mutex> lock(gMutex);

    LOG_DLOPEN_DETAIL("dlclose(%p)", rawHandle);
    if (0 != dlclose(rawHandle)) ALOGE("dlclose(): %s", dlerror());
}

Dlhandle dlopenLibrary() {
    static std::weak_ptr<void> gWeakHandle;

    std::lock_guard<std::mutex> lock(gMutex);
    auto strongHandle = gWeakHandle.lock();
    if (strongHandle != nullptr) return strongHandle;

    void* rawHandle = dlopen(kLibBinderTransport, RTLD_LAZY | RTLD_LOCAL);
    if (rawHandle == nullptr) {
        ALOGE("dlopen(%s): %s", kLibBinderTransport, dlerror());
        return nullptr;
    }
    LOG_DLOPEN_DETAIL("dlopen(%s) -> %p", kLibBinderTransport, rawHandle);
    strongHandle = Dlhandle(rawHandle, dlhandleDeleter);
    gWeakHandle = strongHandle;
    return strongHandle;
}

// A tuple (Dlhandle, RpcTransport) that ensures the internal implementation is destroyed
// before dlclose().
class RpcTransportShim : public RpcTransport {
public:
    RpcTransportShim(Dlhandle handle, std::unique_ptr<RpcTransport> impl)
          : mHandle(std::move(handle)), mImpl(std::move(impl)) {
        LOG_DLOPEN_DETAIL("RpcTransportShim::RpcTransportShim");
    }
    ~RpcTransportShim() { LOG_DLOPEN_DETAIL("RpcTransportShim::~RpcTransportShim"); }
    int send(const void* buf, int size) override {
        LOG_DLOPEN_DETAIL("RpcTransportShim::send");
        return mImpl->send(buf, size);
    }
    int recv(void* buf, int size) override {
        LOG_DLOPEN_DETAIL("RpcTransportShim::recv");
        return mImpl->recv(buf, size);
    }
    int peek(void* buf, int size) override {
        LOG_DLOPEN_DETAIL("RpcTransportShim::peek");
        return mImpl->peek(buf, size);
    }
    bool pending() override {
        LOG_DLOPEN_DETAIL("RpcTransportShim::pending");
        return mImpl->pending();
    }
    android::base::borrowed_fd pollSocket() const override {
        LOG_DLOPEN_DETAIL("RpcTransportShim::pollSocket");
        return mImpl->pollSocket();
    }

private:
    // Order matters. The implementation must be deallocated before the dl handle, because
    // the function that deallocates the implementation lives in the handle.
    Dlhandle mHandle;
    std::unique_ptr<RpcTransport> mImpl;
};

// A tuple (Dlhandle, RpcTransportCtx) that ensures the internal implementation is destroyed
// before dlclose().
class RpcTransportCtxShim : public RpcTransportCtx {
public:
    RpcTransportCtxShim(Dlhandle handle, std::unique_ptr<RpcTransportCtx> impl)
          : mHandle(std::move(handle)), mImpl(std::move(impl)) {
        LOG_DLOPEN_DETAIL("RpcTransportCtxShim::RpcTransportCtxShim");
    }
    ~RpcTransportCtxShim() { LOG_DLOPEN_DETAIL("RpcTransportCtxShim::~RpcTransportCtxShim"); }
    std::unique_ptr<RpcTransport> newTransport(android::base::unique_fd fd) const override {
        LOG_DLOPEN_DETAIL("RpcTransportCtxShim::newTransport");
        return std::make_unique<RpcTransportShim>(mHandle, mImpl->newTransport(std::move(fd)));
    }

private:
    // Order matters. The implementation must be deallocated before the dl handle, because
    // the function that deallocates the implementation lives in the handle.
    Dlhandle mHandle;
    std::unique_ptr<RpcTransportCtx> mImpl;
};

template <typename Fn>
std::unique_ptr<RpcTransportCtx> newRpcTransportCtxTls(const char* fnName) {
    auto lib = dlopenLibrary();
    if (lib == nullptr) return nullptr;
    auto fnPtr = dlsym(lib.get(), fnName);
    if (fnPtr == nullptr) {
        ALOGE("Cannot find symbol %s: %s", fnName, dlerror());
        return nullptr;
    }
    auto fn = reinterpret_cast<Fn>(fnPtr);

    RpcTransportCtx* impl = fn();
    if (impl == nullptr) return nullptr;
    // immediately takes ownership of returned pointer
    auto uImpl = std::unique_ptr<RpcTransportCtx>(impl);

    return std::make_unique<RpcTransportCtxShim>(std::move(lib), std::move(uImpl));
}

} // namespace

std::unique_ptr<RpcTransportCtx> newServerRpcTransportCtx(bool tls) {
    if (tls) {
        return newRpcTransportCtxTls<decltype(&newServerRpcTransportCtxTls)>(
                "newServerRpcTransportCtxTls");
    }
    return newRpcTransportCtxRaw();
}

std::unique_ptr<RpcTransportCtx> newClientRpcTransportCtx(bool tls) {
    if (tls) {
        return newRpcTransportCtxTls<decltype(&newClientRpcTransportCtxTls)>(
                "newClientRpcTransportCtxTls");
    }
    return newRpcTransportCtxRaw();
}

} // namespace android
