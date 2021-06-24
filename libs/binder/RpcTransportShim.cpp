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

#include "RpcTransportRaw.h"
#include "RpcTransportTls.h"

namespace android {

namespace {

using Dlhandle = std::shared_ptr<void>;

constexpr const char* kLibBinderTransport = "libbinder_tls.so";

void dlhandleDeleter(void* rawHandle) {
    if (0 != dlclose(rawHandle)) ALOGE("dlclose(): %s", dlerror());
}

Dlhandle dlopenLibrary(const char* name) {
    void* rawHandle = dlopen(name, RTLD_LAZY | RTLD_LOCAL);
    if (rawHandle == nullptr) {
        ALOGE("dlopen(%s): %s", name, dlerror());
        return nullptr;
    }
    return Dlhandle(rawHandle, dlhandleDeleter);
}

// A tuple (Dlhandle, RpcTransport) that ensures the internal implementation is destroyed
// before dlclose().
class RpcTransportShim : public RpcTransport {
public:
    RpcTransportShim(Dlhandle handle, std::unique_ptr<RpcTransport> impl)
          : mHandle(std::move(handle)), mImpl(std::move(impl)) {}
    int send(const void* buf, int size) override { return mImpl->send(buf, size); }
    int recv(void* buf, int size) override { return mImpl->recv(buf, size); }
    int peek(void* buf, int size) override { return mImpl->peek(buf, size); }
    bool pending() override { return mImpl->pending(); }
    android::base::borrowed_fd pollSocket() const override { return mImpl->pollSocket(); }

private:
    // Order matters. The implementation must be deallocated before the dl handle, because
    // the function that deallocates the implementation lives in the handle.
    Dlhandle mHandle;
    std::unique_ptr<RpcTransport> mImpl;
};

template <typename Fn, typename... Args>
std::unique_ptr<RpcTransport> newRpcTransportTls(const char* fnName, Args&&... args) {
    auto lib = dlopenLibrary(kLibBinderTransport);
    if (lib == nullptr) return nullptr;
    auto fnPtr = dlsym(lib.get(), fnName);
    if (fnPtr == nullptr) {
        ALOGE("Cannot find symbol %s: %s", fnName, dlerror());
        return nullptr;
    }
    auto fn = reinterpret_cast<Fn>(fnPtr);

    RpcTransport* impl = fn(std::forward<Args>(args)...);
    if (impl == nullptr) return nullptr;
    // immediately takes ownership of returned pointer
    auto uImpl = std::unique_ptr<RpcTransport>(impl);

    return std::make_unique<RpcTransportShim>(std::move(lib), std::move(uImpl));
}

} // namespace

std::unique_ptr<RpcTransport> newServerRpcTransport(bool tls, android::base::unique_fd acceptedFd) {
    if (tls) {
        return newRpcTransportTls<decltype(&newServerRpcTransportTls)>("newServerRpcTransportTls",
                                                                       std::move(acceptedFd));
    }
    return newServerRpcTransportRaw(std::move(acceptedFd));
}

std::unique_ptr<RpcTransport> newClientRpcTransport(bool tls,
                                                    android::base::unique_fd connectedFd) {
    if (tls) {
        return newRpcTransportTls<decltype(&newClientRpcTransportTls)>("newClientRpcTransportTls",
                                                                       std::move(connectedFd));
    }
    return newClientRpcTransportRaw(std::move(connectedFd));
}

} // namespace android
