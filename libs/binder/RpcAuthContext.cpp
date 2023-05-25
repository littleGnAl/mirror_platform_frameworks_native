/*
 * Copyright (C) 2005 The Android Open Source Project
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

#define LOG_TAG "RpcAuthContext"

#include <binder/RpcAuthContext.h>

#include <utils/Log.h>

#include <pthread.h>
#include <atomic>

// ---------------------------------------------------------------------------

namespace android {

static pthread_mutex_t gTLSMutex = PTHREAD_MUTEX_INITIALIZER;
static std::atomic<bool> gHaveTLS(false);
static pthread_key_t gTLS = 0;

RpcAuthContext::RpcAuthContext() {
    pthread_setspecific(gTLS, this);
    clearCallingSid();
}

RpcAuthContext::~RpcAuthContext() {}

RpcAuthContext* RpcAuthContext::self() {
    if (gHaveTLS.load(std::memory_order_acquire)) {
    restart:
        const pthread_key_t k = gTLS;
        RpcAuthContext* ctx = (RpcAuthContext*)pthread_getspecific(k);
        if (ctx) return ctx;
        return new RpcAuthContext;
    }

    pthread_mutex_lock(&gTLSMutex);
    if (!gHaveTLS.load(std::memory_order_relaxed)) {
        int key_create_value = pthread_key_create(&gTLS, threadDestructor);
        if (key_create_value != 0) {
            pthread_mutex_unlock(&gTLSMutex);
            ALOGW("RpcAuthContext::self() unable to create TLS key, expect a crash: %s\n",
                  strerror(key_create_value));
            return nullptr;
        }
        gHaveTLS.store(true, std::memory_order_release);
    }
    pthread_mutex_unlock(&gTLSMutex);
    goto restart;
}

void RpcAuthContext::threadDestructor(void* ctx) {
    ALOGI("RpcAuthContext is destructed with thread");
    RpcAuthContext* const self = static_cast<RpcAuthContext*>(ctx);
    if (self) {
        delete self;
    }
}

int64_t RpcAuthContext::getCallingSid() const {
    return mCallingSid;
}

void RpcAuthContext::restoreCallingSid(int64_t sid) {
    mCallingSid = sid;
}

void RpcAuthContext::clearCallingSid() {
    mCallingSid = 0;
}

} // namespace android
