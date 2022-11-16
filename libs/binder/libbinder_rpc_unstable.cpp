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

#include <binder_rpc_unstable.hpp>

#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <android/binder_libbinder.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>
#include <cutils/sockets.h>
#include <linux/vm_sockets.h>

#include <unordered_map>

using android::OK;
using android::RpcServer;
using android::RpcSession;
using android::status_t;
using android::statusToString;
using android::base::unique_fd;

static std::unordered_map<RpcServerHandle, android::sp<RpcServer>> sInstances;
static android::RpcMutex sInstancesLock;

static android::sp<RpcServer> getRpcServer(RpcServerHandle handle) {
    return android::sp<RpcServer>::fromExisting(reinterpret_cast<RpcServer*>(handle));
}

static RpcServerHandle startRpcServer(android::sp<RpcServer> server, AIBinder* service) {
    server->setRootObject(AIBinder_toPlatformBinder(service));
    auto handle = reinterpret_cast<RpcServerHandle>(server.get());
    {
        android::RpcMutexLockGuard _l(sInstancesLock);
        auto success = sInstances.insert({handle, std::move(server)});
        LOG_ALWAYS_FATAL_IF(!success.second, "RpcServer instance already exists");
    }
    return handle;
}

extern "C" {

bool RunVsockRpcServerWithFactory(AIBinder* (*factory)(unsigned int cid, void* context),
                                  void* factoryContext, unsigned int port) {
    auto server = RpcServer::make();
    if (status_t status = server->setupVsockServer(port); status != OK) {
        LOG(ERROR) << "Failed to set up vsock server with port " << port
                   << " error: " << statusToString(status).c_str();
        return false;
    }
    server->setPerSessionRootObject([=](const void* addr, size_t addrlen) {
        LOG_ALWAYS_FATAL_IF(addrlen < sizeof(sockaddr_vm), "sockaddr is truncated");
        const sockaddr_vm* vaddr = reinterpret_cast<const sockaddr_vm*>(addr);
        LOG_ALWAYS_FATAL_IF(vaddr->svm_family != AF_VSOCK, "address is not a vsock");
        return AIBinder_toPlatformBinder(factory(vaddr->svm_cid, factoryContext));
    });

    server->join();

    // Shutdown any open sessions since server failed.
    (void)server->shutdown();
    return true;
}

RpcServerHandle VsockRpcServer(AIBinder* service, unsigned int port) {
    auto server = RpcServer::make();
    if (status_t status = server->setupVsockServer(port); status != OK) {
        LOG(ERROR) << "Failed to set up vsock server with port " << port
                   << " error: " << statusToString(status).c_str();
        return RPC_SERVER_HANDLE_INVALID;
    }
    return startRpcServer(std::move(server), service);
}

AIBinder* VsockRpcClient(unsigned int cid, unsigned int port) {
    auto session = RpcSession::make();
    if (status_t status = session->setupVsockClient(cid, port); status != OK) {
        LOG(ERROR) << "Failed to set up vsock client with CID " << cid << " and port " << port
                   << " error: " << statusToString(status).c_str();
        return nullptr;
    }
    return AIBinder_fromPlatformBinder(session->getRootObject());
}

RpcServerHandle InitUnixDomainRpcServer(AIBinder* service, const char* name) {
    auto server = RpcServer::make();
    auto fd = unique_fd(android_get_control_socket(name));
    if (status_t status = server->setupRawSocketServer(std::move(fd)); status != OK) {
        LOG(ERROR) << "Failed to set up Unix Domain RPC server with name " << name
                   << " error: " << statusToString(status).c_str();
        return RPC_SERVER_HANDLE_INVALID;
    }
    return startRpcServer(std::move(server), service);
}

AIBinder* UnixDomainRpcClient(const char* name) {
    std::string pathname(name);
    pathname = ANDROID_SOCKET_DIR "/" + pathname;
    auto session = RpcSession::make();
    if (status_t status = session->setupUnixDomainClient(pathname.c_str()); status != OK) {
        LOG(ERROR) << "Failed to set up Unix Domain RPC client with path: " << pathname
                   << " error: " << statusToString(status).c_str();
        return nullptr;
    }
    return AIBinder_fromPlatformBinder(session->getRootObject());
}

AIBinder* RpcPreconnectedClient(int (*requestFd)(void* param), void* param) {
    auto session = RpcSession::make();
    auto request = [=] { return unique_fd{requestFd(param)}; };
    if (status_t status = session->setupPreconnectedClient(unique_fd{}, request); status != OK) {
        LOG(ERROR) << "Failed to set up vsock client. error: " << statusToString(status).c_str();
        return nullptr;
    }
    return AIBinder_fromPlatformBinder(session->getRootObject());
}

void JoinRpcServer(RpcServerHandle handle) {
    getRpcServer(handle)->join();
}

void ShutdownRpcServer(RpcServerHandle handle) {
    getRpcServer(handle)->shutdown();
    {
        android::RpcMutexLockGuard _l(sInstancesLock);
        auto removed = sInstances.erase(handle);
        LOG_ALWAYS_FATAL_IF(removed < 1, "RpcServer instance not found");
        LOG_ALWAYS_FATAL_IF(removed > 1, "Multiple RpcServer instance with the same handle");
    }
}
}
