/*
 * Copyright (C) 2020 The Android Open Source Project
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

#define LOG_TAG "RpcServer"

#include <uapi/err.h>

#include <android-base/file.h>
#include <android-base/hex.h>
#include <android-base/scopeguard.h>
#include <binder/Parcel.h>
#include <binder/RpcServer.h>
#include <binder/RpcTransportTrusty.h>
#include <log/log.h>

#include <openssl/rand.h>

#include "../FdTrigger.h"
#include "../RpcSocketAddress.h"
#include "../RpcState.h"
#include "../RpcWireFormat.h"

namespace android {

constexpr size_t kSessionIdBytes = 32;

using base::ScopeGuard;
using base::unique_fd;

RpcServer::RpcServer(std::unique_ptr<RpcTransportCtx> ctx) : mCtx(std::move(ctx)) {}
RpcServer::~RpcServer() {
    (void)shutdown();
}

sp<RpcServer> RpcServer::make(std::unique_ptr<RpcTransportCtxFactory> rpcTransportCtxFactory) {
    // Default is without TLS.
    if (rpcTransportCtxFactory == nullptr)
        rpcTransportCtxFactory = RpcTransportCtxFactoryTrusty::make();
    auto ctx = rpcTransportCtxFactory->newServerCtx();
    if (ctx == nullptr) return nullptr;
    return sp<RpcServer>::make(std::move(ctx));
}

status_t RpcServer::setupTrustyServer(tipc_hset* hset, const char* port,
                                      const struct tipc_port_acl* acl, size_t msg_max_size) {
    /* TODO: copy the port name??? */
    mTipcPort.name = port;
    mTipcPort.msg_max_size = msg_max_size;
    mTipcPort.msg_queue_len = 6; // Three each way
    mTipcPort.acl = acl;
    mTipcPort.priv = this;

    int rc = tipc_add_service(hset, &mTipcPort, 1, 1, &kTipcOps);
    return RpcSession::statusFromTrusty(rc);
}

void RpcServer::setProtocolVersion(uint32_t version) {
    mProtocolVersion = version;
}

void RpcServer::setRootObject(const sp<IBinder>& binder) {
    mRootObjectFactory = nullptr;
    mRootObjectWeak = mRootObject = binder;
}

void RpcServer::setRootObjectWeak(const wp<IBinder>& binder) {
    mRootObject.clear();
    mRootObjectFactory = nullptr;
    mRootObjectWeak = binder;
}
void RpcServer::setPerSessionRootObject(std::function<sp<IBinder>(const uuid*)>&& makeObject) {
    mRootObject.clear();
    mRootObjectWeak.clear();
    mRootObjectFactory = std::move(makeObject);
}

sp<IBinder> RpcServer::getRootObject() {
    bool hasWeak = mRootObjectWeak.unsafe_get();
    sp<IBinder> ret = mRootObjectWeak.promote();
    ALOGW_IF(hasWeak && ret == nullptr, "RpcServer root object is freed, returning nullptr");
    return ret;
}

bool RpcServer::shutdown() {
    /* TODO: do this for Trusty */
    return true;
}

bool RpcServer::hasServer() {
    return mServer.ok();
}

unique_fd RpcServer::releaseServer() {
    return std::move(mServer);
}

int RpcServer::handleConnect(const tipc_port* port, handle_t chan, const uuid* peer, void** ctx_p) {
    auto* server = reinterpret_cast<RpcServer*>(const_cast<void*>(port->priv));

#if 0 // TODO: re-enable when triggers are supported
    // mShutdownTrigger can only be cleared once connection threads have joined.
    // It must be set before this thread is started
    LOG_ALWAYS_FATAL_IF(server->mShutdownTrigger == nullptr);
#endif
    LOG_ALWAYS_FATAL_IF(server->mCtx == nullptr);

    status_t status = OK;

    unique_fd clientFd(chan);
    auto client = server->mCtx->newTransport(std::move(clientFd), server->mShutdownTrigger.get());
    if (client == nullptr) {
        ALOGE("Dropping connected channel");
        status = DEAD_OBJECT;
        // still need to cleanup before we can return
    } else {
        LOG_RPC_DETAIL("Created RpcTransport %p for client fd %d", client.get(), chan);
    }

    RpcConnectionHeader header;
    if (status == OK) {
        iovec iov{&header, sizeof(header)};
        status = client->interruptableReadFully(server->mShutdownTrigger.get(), &iov, 1, {});
        if (status != OK) {
            ALOGE("Failed to read ID for client connecting to RPC server: %s",
                  statusToString(status).c_str());
            // still need to cleanup before we can return
        }
    }
    LOG_RPC_DETAIL("RpcConnection header version:%u options:%x session:%u", header.version,
                   (int)header.options, (unsigned)header.sessionIdSize);

    std::vector<uint8_t> sessionId;
    if (status == OK) {
        if (header.sessionIdSize > 0) {
            if (header.sessionIdSize == kSessionIdBytes) {
                sessionId.resize(header.sessionIdSize);
                iovec iov{sessionId.data(), sessionId.size()};
                status =
                        client->interruptableReadFully(server->mShutdownTrigger.get(), &iov, 1, {});
                if (status != OK) {
                    ALOGE("Failed to read session ID for client connecting to RPC server: %s",
                          statusToString(status).c_str());
                    // still need to cleanup before we can return
                }
            } else {
                ALOGE("Malformed session ID. Expecting session ID of size %zu but got %" PRIu16,
                      kSessionIdBytes, header.sessionIdSize);
                status = BAD_VALUE;
            }
        }
    }

    bool incoming = false;
    uint32_t protocolVersion = 0;
    bool requestingNewSession = false;

    if (status == OK) {
        incoming = header.options & RPC_CONNECTION_OPTION_INCOMING;
        protocolVersion = std::min(header.version,
                                   server->mProtocolVersion.value_or(RPC_WIRE_PROTOCOL_VERSION));
        requestingNewSession = sessionId.empty();

        if (requestingNewSession) {
            RpcNewSessionResponse response{
                    .version = protocolVersion,
            };

            iovec iov{&response, sizeof(response)};
            status = client->interruptableWriteFully(server->mShutdownTrigger.get(), &iov, 1, {});
            if (status != OK) {
                ALOGE("Failed to send new session response: %s", statusToString(status).c_str());
                // still need to cleanup before we can return
            }
        }
    }

    if (status != OK || server->mShutdownTrigger->isTriggered()) {
        return RpcSession::statusToTrusty(status);
    }

    sp<RpcSession> session;
    if (requestingNewSession) {
        if (incoming) {
            ALOGE("Cannot create a new session with an incoming connection, would leak");
            return ERR_NOT_VALID;
        }

        // Uniquely identify session at the application layer. Even if a
        // client/server use the same certificates, if they create multiple
        // sessions, we still want to distinguish between them.
        sessionId.resize(kSessionIdBytes);
        size_t tries = 0;
        do {
            // don't block if there is some entropy issue
            if (tries++ > 5) {
                ALOGE("Cannot find new address: %s",
                      base::HexString(sessionId.data(), sessionId.size()).c_str());
                return ERR_NO_RESOURCES;
            }

            RAND_bytes(sessionId.data(), kSessionIdBytes);
        } while (server->mSessions.end() != server->mSessions.find(sessionId));

        session = RpcSession::make();
        if (!session->setProtocolVersion(protocolVersion)) return ERR_INVALID_ARGS;

        // if null, falls back to server root
        sp<IBinder> sessionSpecificRoot;
        if (server->mRootObjectFactory != nullptr) {
            sessionSpecificRoot = server->mRootObjectFactory(peer);
            if (sessionSpecificRoot == nullptr) {
                ALOGE("Warning: server returned null from root object factory");
            }
        }

        if (!session->setForServer(server, sessionId, sessionSpecificRoot)) {
            ALOGE("Failed to attach server to session");
            return ERR_GENERIC;
        }

        server->mSessions[sessionId] = session;
    } else {
        auto it = server->mSessions.find(sessionId);
        if (it == server->mSessions.end()) {
            ALOGE("Cannot add thread, no record of session with ID %s",
                  base::HexString(sessionId.data(), sessionId.size()).c_str());
            return ERR_NOT_FOUND;
        }
        session = it->second;
    }

    /* Save the session for easy access */
    *ctx_p = session.get();

    // incoming for the peer == outgoing from our side
    LOG_ALWAYS_FATAL_IF(OK != session->addConnection(std::move(client), incoming),
                        "server state must already be initialized");

    return NO_ERROR;
}

int RpcServer::handleMessage(const tipc_port* port, handle_t chan, void* ctx) {
    auto* session = reinterpret_cast<RpcSession*>(ctx);
    status_t status = session->state()->drainCommands(session->mConnection, session,
                                                      RpcState::CommandType::ANY);
    if (status != OK) {
        LOG_RPC_DETAIL("Binder connection thread closing w/ status %s",
                       statusToString(status).c_str());
    }

    return NO_ERROR;
}

void RpcServer::handleDisconnect(const tipc_port* port, handle_t chan, void* ctx) {}

void RpcServer::handleChannelCleanup(void* ctx) {
    auto* session = reinterpret_cast<RpcSession*>(ctx);
    session->server()->mSessions.erase(session->mId);
}

} // namespace android
