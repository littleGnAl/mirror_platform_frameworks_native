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

#include "binderRpcTestCommon.h"

namespace android {

std::atomic<int32_t> MyBinderRpcSession::gNum;
sp<IBinder> MyBinderRpcTest::mHeldBinder;

extern "C" void runService(const BinderRpcOptions& options, SocketType socketType,
                           RpcSecurity rpcSecurity, unsigned int vsockPort, const std::string& addr,
                           android::base::borrowed_fd writeEnd,
                           android::base::borrowed_fd readEnd) {
    auto certVerifier = std::make_shared<RpcCertificateVerifierSimple>();
    sp<RpcServer> server = RpcServer::make(newFactory(rpcSecurity, certVerifier));

    server->setMaxThreads(options.numThreads);

    unsigned int outPort = 0;

    switch (socketType) {
        case SocketType::PRECONNECTED:
            [[fallthrough]];
        case SocketType::UNIX:
            CHECK_EQ(OK, server->setupUnixDomainServer(addr.c_str())) << addr;
            break;
        case SocketType::VSOCK:
            CHECK_EQ(OK, server->setupVsockServer(vsockPort));
            break;
        case SocketType::INET: {
            CHECK_EQ(OK, server->setupInetServer(kLocalInetAddress, 0, &outPort));
            CHECK_NE(0, outPort);
            break;
        }
        default:
            LOG_ALWAYS_FATAL("Unknown socket type");
    }

    BinderRpcTestServerInfo serverInfo;
    serverInfo.port = static_cast<int64_t>(outPort);
    serverInfo.cert.data = server->getCertificate(RpcCertificateFormat::PEM);
    writeToFd(writeEnd, serverInfo);
    auto clientInfo = readFromFd<BinderRpcTestClientInfo>(readEnd);

    if (rpcSecurity == RpcSecurity::TLS) {
        for (const auto& clientCert : clientInfo.certs) {
            CHECK_EQ(OK,
                     certVerifier->addTrustedPeerCertificate(RpcCertificateFormat::PEM,
                                                             clientCert.data));
        }
    }

    server->setPerSessionRootObject([&](const void* addrPtr, size_t len) {
        // UNIX sockets with abstract addresses return
        // sizeof(sa_family_t)==2 in addrlen
        CHECK_GE(len, sizeof(sa_family_t));
        const sockaddr* addr = reinterpret_cast<const sockaddr*>(addrPtr);
        sp<MyBinderRpcTest> service = sp<MyBinderRpcTest>::make();
        switch (addr->sa_family) {
            case AF_UNIX:
                // nothing to save
                break;
            case AF_VSOCK:
                CHECK_EQ(len, sizeof(sockaddr_vm));
                service->port = reinterpret_cast<const sockaddr_vm*>(addr)->svm_port;
                break;
            case AF_INET:
                CHECK_EQ(len, sizeof(sockaddr_in));
                service->port = ntohs(reinterpret_cast<const sockaddr_in*>(addr)->sin_port);
                break;
            case AF_INET6:
                CHECK_EQ(len, sizeof(sockaddr_in));
                service->port = ntohs(reinterpret_cast<const sockaddr_in6*>(addr)->sin6_port);
                break;
            default:
                LOG_ALWAYS_FATAL("Unrecognized address family %d", addr->sa_family);
        }
        service->server = server;
        return service;
    });

    server->join();

    // Another thread calls shutdown. Wait for it to complete.
    (void)server->shutdown();
}

} // namespace android
