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

#define LOG_TAG "RpcServerTrusty"

#include <binder/Parcel.h>
#include <binder/RpcServer.h>
#include <binder/RpcServerTrusty.h>
#include <binder/RpcThreads.h>
#include <binder/RpcTransportTipcTrusty.h>
#include <lib/binary_search_tree.h>
#include <log/log.h>

#include "../FdTrigger.h"
#include "../RpcState.h"
#include "TrustyStatus.h"

using android::base::unexpected;

namespace android {

class RpcServerTrusty::BstRoot {
public:
    struct bst_root mRoot;
};

class RpcServerTrusty::BstNode {
public:
    BstNode(std::string&& portName) : mNode(BST_NODE_INITIAL_VALUE), mPortName(portName){};
    BstNode(android::sp<RpcServerTrusty>&& server)
          : mNode(BST_NODE_INITIAL_VALUE), mServer(server) {
        bst_insert(&RpcServerTrusty::mServerSearchTree->mRoot, &mNode, compareServersByPort);
    };
    ~BstNode() {
        if (mServer.get()) {
            bst_delete(&RpcServerTrusty::mServerSearchTree->mRoot, &mNode);
        }
    }

private:
    struct bst_node mNode;
    std::string mPortName;
    android::sp<RpcServerTrusty> mServer;
    friend RpcServerTrusty;
    std::string& getPortName() {
        if (mServer.get()) {
            return mServer->mPortName;
        }
        return mPortName;
    }
    static int compareServersByPort(struct bst_node* a, struct bst_node* b) {
        auto container_a = containerof(a, RpcServerTrusty::BstNode, mNode);
        auto container_b = containerof(b, RpcServerTrusty::BstNode, mNode);
        return container_a->getPortName().compare(container_b->getPortName());
    }
};

auto RpcServerTrusty::mServerSearchTree = std::make_unique<RpcServerTrusty::BstRoot>();

android::base::expected<sp<RpcServerTrusty>, int> RpcServerTrusty::make(
        tipc_hset* handleSet, std::string&& portName, std::shared_ptr<const PortAcl>&& portAcl,
        size_t msgMaxSize, std::unique_ptr<RpcTransportCtxFactory> rpcTransportCtxFactory) {
    // Default is without TLS.
    if (rpcTransportCtxFactory == nullptr)
        rpcTransportCtxFactory = RpcTransportCtxFactoryTipcTrusty::make();
    auto ctx = rpcTransportCtxFactory->newServerCtx();
    if (ctx == nullptr) {
        return unexpected(ERR_NO_MEMORY);
    }

    auto srv = sp<RpcServerTrusty>::make(std::move(ctx), std::move(portName), std::move(portAcl),
                                         msgMaxSize);
    if (srv == nullptr) {
        return unexpected(ERR_NO_MEMORY);
    }

    int rc = tipc_add_service(handleSet, &srv->mTipcPort, 1, 0, &kTipcOps);
    if (rc != NO_ERROR) {
        return unexpected(rc);
    }
    return srv;
}

android::base::expected<sp<RpcServerTrusty>, int> RpcServerTrusty::get(std::string&& portName) {
    std::unique_ptr<RpcServerTrusty::BstNode> dummyNode =
            std::make_unique<RpcServerTrusty::BstNode>(std::move(portName));
    auto node = bst_search(&RpcServerTrusty::mServerSearchTree->mRoot, &dummyNode->mNode,
                           RpcServerTrusty::BstNode::compareServersByPort);
    if (node == nullptr) {
        return unexpected(ERR_NOT_FOUND);
    }
    return containerof(node, RpcServerTrusty::BstNode, mNode)->mServer;
}

RpcServerTrusty::RpcServerTrusty(std::unique_ptr<RpcTransportCtx> ctx, std::string&& portName,
                                 std::shared_ptr<const PortAcl>&& portAcl, size_t msgMaxSize)
      : mServerSearchTreeNode(std::make_unique<RpcServerTrusty::BstNode>(this)),
        mRpcServer(sp<RpcServer>::make(std::move(ctx))),
        mPortName(std::move(portName)),
        mPortAcl(std::move(portAcl)) {
    mTipcPort.name = mPortName.c_str();
    mTipcPort.msg_max_size = msgMaxSize;
    mTipcPort.msg_queue_len = 6; // Three each way
    mTipcPort.priv = this;

    if (mPortAcl) {
        // Initialize the array of pointers to uuids.
        // The pointers in mUuidPtrs should stay valid across moves of
        // RpcServerTrusty (the addresses of a std::vector's elements
        // shouldn't change when the vector is moved), but would be invalidated
        // by a copy which is why we disable the copy constructor and assignment
        // operator for RpcServerTrusty.
        auto numUuids = mPortAcl->uuids.size();
        mUuidPtrs.resize(numUuids);
        for (size_t i = 0; i < numUuids; i++) {
            mUuidPtrs[i] = &mPortAcl->uuids[i];
        }

        // Copy the contents of portAcl into the tipc_port_acl structure that we
        // pass to tipc_add_service
        mTipcPortAcl.flags = mPortAcl->flags;
        mTipcPortAcl.uuid_num = numUuids;
        mTipcPortAcl.uuids = mUuidPtrs.data();
        mTipcPortAcl.extra_data = mPortAcl->extraData;

        mTipcPort.acl = &mTipcPortAcl;
    } else {
        mTipcPort.acl = nullptr;
    }
}

int RpcServerTrusty::handleConnect(const tipc_port* port, handle_t chan, const uuid* peer,
                                   void** ctx_p) {
    auto* server = reinterpret_cast<RpcServerTrusty*>(const_cast<void*>(port->priv));
    server->mRpcServer->mShutdownTrigger = FdTrigger::make();
    server->mRpcServer->mConnectingThreads[rpc_this_thread::get_id()] = RpcMaybeThread();

    int rc = NO_ERROR;
    auto joinFn = [&](sp<RpcSession>&& session, RpcSession::PreJoinSetupResult&& result) {
        if (result.status != OK) {
            rc = statusToTrusty(result.status);
            return;
        }

        /* Save the session and connection for the other callbacks */
        auto* channelContext = new (std::nothrow) ChannelContext;
        if (channelContext == nullptr) {
            rc = ERR_NO_MEMORY;
            return;
        }

        channelContext->session = std::move(session);
        channelContext->connection = std::move(result.connection);

        *ctx_p = channelContext;
    };

    base::unique_fd clientFd(chan);
    android::RpcTransportFd transportFd(std::move(clientFd));

    std::array<uint8_t, RpcServer::kRpcAddressSize> addr;
    constexpr size_t addrLen = sizeof(*peer);
    memcpy(addr.data(), peer, addrLen);
    RpcServer::establishConnection(sp(server->mRpcServer), std::move(transportFd), addr, addrLen,
                                   joinFn);

    return rc;
}

int RpcServerTrusty::handleMessage(const tipc_port* /*port*/, handle_t /*chan*/, void* ctx) {
    auto* channelContext = reinterpret_cast<ChannelContext*>(ctx);
    LOG_ALWAYS_FATAL_IF(channelContext == nullptr,
                        "bad state: message received on uninitialized channel");

    auto& session = channelContext->session;
    auto& connection = channelContext->connection;
    status_t status =
            session->state()->drainCommands(connection, session, RpcState::CommandType::ANY);
    if (status != OK) {
        LOG_RPC_DETAIL("Binder connection thread closing w/ status %s",
                       statusToString(status).c_str());
    }

    return NO_ERROR;
}

void RpcServerTrusty::handleDisconnect(const tipc_port* /*port*/, handle_t /*chan*/,
                                       void* /*ctx*/) {}

void RpcServerTrusty::handleChannelCleanup(void* ctx) {
    auto* channelContext = reinterpret_cast<ChannelContext*>(ctx);
    if (channelContext == nullptr) {
        return;
    }

    auto& session = channelContext->session;
    auto& connection = channelContext->connection;
    LOG_ALWAYS_FATAL_IF(!session->removeIncomingConnection(connection),
                        "bad state: connection object guaranteed to be in list");

    delete channelContext;
}

} // namespace android
