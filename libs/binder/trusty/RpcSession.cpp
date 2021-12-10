/*
 * Copyright (C) 2022 The Android Open Source Project
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

#define LOG_TAG "RpcSession"

#include <trusty_ipc.h>
#include <uapi/err.h>

#include <binder/RpcSession.h>

#include <android-base/hex.h>
#include <android-base/macros.h>
#include <android-base/scopeguard.h>
#include <binder/BpBinder.h>
#include <binder/Parcel.h>
#include <binder/RpcServer.h>
#include <binder/RpcTransportTrusty.h>
#include <binder/Stability.h>

#include "../FdTrigger.h"
#include "../RpcSocketAddress.h"
#include "../RpcState.h"
#include "../RpcWireFormat.h"
#include "../Utils.h"

namespace android {

using base::unique_fd;

RpcSession::RpcSession(std::unique_ptr<RpcTransportCtx> ctx) : mCtx(std::move(ctx)) {
    LOG_RPC_DETAIL("RpcSession created %p", this);

    mRpcBinderState = std::make_unique<RpcState>();
}

RpcSession::~RpcSession() {
    LOG_RPC_DETAIL("RpcSession destroyed %p", this);
}

sp<RpcSession> RpcSession::make() {
    return make(RpcTransportCtxFactoryTrusty::make());
}

sp<RpcSession> RpcSession::make(std::unique_ptr<RpcTransportCtxFactory> rpcTransportCtxFactory) {
    auto ctx = rpcTransportCtxFactory->newClientCtx();
    if (ctx == nullptr) return nullptr;
    return sp<RpcSession>::make(std::move(ctx));
}

bool RpcSession::setProtocolVersion(uint32_t version) {
    if (version >= RPC_WIRE_PROTOCOL_VERSION_NEXT &&
        version != RPC_WIRE_PROTOCOL_VERSION_EXPERIMENTAL) {
        ALOGE("Cannot start RPC session with version %u which is unknown (current protocol version "
              "is %u).",
              version, RPC_WIRE_PROTOCOL_VERSION);
        return false;
    }

    if (mProtocolVersion && version > *mProtocolVersion) {
        ALOGE("Cannot upgrade explicitly capped protocol version %u to newer version %u",
              *mProtocolVersion, version);
        return false;
    }

    mProtocolVersion = version;
    return true;
}

std::optional<uint32_t> RpcSession::getProtocolVersion() {
    return mProtocolVersion;
}

status_t RpcSession::setupTrustyClient(const char* port) {
    int rc = connect(port, IPC_CONNECT_WAIT_FOR_PORT);
    if (rc < 0) {
        return statusFromTrusty(rc);
    }

    if (mShutdownTrigger == nullptr) {
        mShutdownTrigger = FdTrigger::make();
        if (mShutdownTrigger == nullptr) return INVALID_OPERATION;
    }

    auto oldProtocolVersion = mProtocolVersion;
    auto cleanup = base::ScopeGuard([&] {
        // if any threads are started, shut them down
        (void)shutdownAndWait(true);

        mId.clear();

        mShutdownTrigger = nullptr;
        mRpcBinderState = std::make_unique<RpcState>();

        // protocol version may have been downgraded - if we reuse this object
        // to connect to another server, force that server to request a
        // downgrade again
        mProtocolVersion = oldProtocolVersion;

        mConnection.clear();
    });

    unique_fd fd(rc);
    mConnection = sp<RpcConnection>::make();
    mConnection->rpcTransport = mCtx->newTransport(std::move(fd), mShutdownTrigger.get());
    if (mConnection->rpcTransport == nullptr) {
        ALOGE("%s: Unable to set up RpcTransport", __PRETTY_FUNCTION__);
        return UNKNOWN_ERROR;
    }

    LOG_RPC_DETAIL("Socket at client with RpcTransport %p", mConnection->rpcTransport.get());

    RpcConnectionHeader header{
            .version = mProtocolVersion.value_or(RPC_WIRE_PROTOCOL_VERSION),
            .options = 0,
            .sessionIdSize = 0,
    };

    iovec headerIov{&header, sizeof(header)};
    auto sendHeaderStatus =
            mConnection->rpcTransport->interruptableWriteFully(mShutdownTrigger.get(), &headerIov,
                                                               1, {});
    if (sendHeaderStatus != OK) {
        ALOGE("Could not write connection header to socket: %s",
              statusToString(sendHeaderStatus).c_str());
        return sendHeaderStatus;
    }

    LOG_RPC_DETAIL("Socket at client: header sent");

    auto sendInitStatus =
            mRpcBinderState->sendConnectionInit(mConnection, sp<RpcSession>::fromExisting(this));
    if (sendInitStatus != OK) {
        ALOGE("Could not send connection init: %s", statusToString(sendInitStatus).c_str());
        return sendInitStatus;
    }

    uint32_t version;
    if (status_t status =
                state()->readNewSessionResponse(mConnection.get(),
                                                sp<RpcSession>::fromExisting(this), &version);
        status != OK)
        return status;
    if (!setProtocolVersion(version)) return BAD_VALUE;

    if (status_t status = readId(); status != OK) {
        ALOGE("Could not get session id after initial session setup: %s",
              statusToString(status).c_str());
        return status;
    }

    cleanup.Disable();

    return OK;
}

sp<IBinder> RpcSession::getRootObject() {
    return state()->getRootObject(mConnection.get(), sp<RpcSession>::fromExisting(this));
}

status_t RpcSession::getRemoteMaxThreads(size_t* maxThreads) {
    return state()->getMaxThreads(mConnection.get(), sp<RpcSession>::fromExisting(this),
                                  maxThreads);
}

bool RpcSession::shutdownAndWait(bool wait) {
    // TODO: shut down cleanly
    return true;
}

status_t RpcSession::transact(const sp<IBinder>& binder, uint32_t code, const Parcel& data,
                              Parcel* reply, uint32_t flags) {
    return state()->transact(mConnection.get(), binder, code, data,
                             sp<RpcSession>::fromExisting(this), reply, flags);
}

status_t RpcSession::sendDecStrong(const BpBinder* binder) {
    // target is 0 because this is used to free BpBinder objects
    return sendDecStrongToTarget(binder->getPrivateAccessor().rpcAddress(), 0 /*target*/);
}

status_t RpcSession::sendDecStrongToTarget(uint64_t address, size_t target) {
    return state()->sendDecStrongToTarget(mConnection.get(), sp<RpcSession>::fromExisting(this),
                                          address, target);
}

sp<RpcServer> RpcSession::server() {
    RpcServer* unsafeServer = mForServer.unsafe_get();
    sp<RpcServer> server = mForServer.promote();

    LOG_ALWAYS_FATAL_IF((unsafeServer == nullptr) != (server == nullptr),
                        "wp<> is to avoid strong cycle only");
    return server;
}

status_t RpcSession::statusFromTrusty(int rc) {
    LOG_RPC_DETAIL("Trusty error: %d", rc);
    switch (rc) {
        case NO_ERROR:
            return OK;
        /* TODO: more errors */
        default:
            return UNKNOWN_ERROR;
    }
}

int RpcSession::statusToTrusty(status_t status) {
    switch (status) {
        case OK:
            return NO_ERROR;
        /* TODO: more errors */
        default:
            return ERR_GENERIC;
    }
}

status_t RpcSession::readId() {
    LOG_ALWAYS_FATAL_IF(mForServer != nullptr, "Can only update ID for client.");

    status_t status =
            state()->getSessionId(mConnection.get(), sp<RpcSession>::fromExisting(this), &mId);
    if (status != OK) return status;

    LOG_RPC_DETAIL("RpcSession %p has id %s", this,
                   base::HexString(mId.data(), mId.size()).c_str());
    return OK;
}

status_t RpcSession::addIncomingConnection(std::unique_ptr<RpcTransport> rpcTransport) {
    mConnection = sp<RpcConnection>::make();
    mConnection->rpcTransport = std::move(rpcTransport);

    return mRpcBinderState->readConnectionInit(mConnection,
                                               sp<RpcSession>::fromExisting(this));
}

bool RpcSession::setForServer(const wp<RpcServer>& server, const std::vector<uint8_t>& sessionId,
                              const sp<IBinder>& sessionSpecificRoot) {
    LOG_ALWAYS_FATAL_IF(mForServer != nullptr);
    LOG_ALWAYS_FATAL_IF(server == nullptr);
    LOG_ALWAYS_FATAL_IF(mShutdownTrigger != nullptr);

    mShutdownTrigger = FdTrigger::make();
    if (mShutdownTrigger == nullptr) return false;

    mId = sessionId;
    mForServer = server;
    mSessionSpecificRootObject = sessionSpecificRoot;
    return true;
}

} // namespace android
