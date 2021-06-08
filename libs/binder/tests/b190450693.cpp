#include <gtest/gtest.h>
#include <binder/IServiceManager.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>

using namespace android;

TEST(Rpc, b190450693) {
    sp<IServiceManager> sm = defaultServiceManager();
    auto binder = sm->checkService(String16("DockObserver"));
    ASSERT_NE(nullptr, binder);
    ASSERT_EQ(String16(), binder->getInterfaceDescriptor());
    ASSERT_EQ(OK, binder->pingBinder());

    auto rpcServer = RpcServer::make();
    rpcServer->iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction();
    unsigned int port;
    ASSERT_TRUE(rpcServer->setupInetServer(0, &port));
    auto socket = rpcServer->releaseServer();
    ASSERT_EQ(OK, binder->setRpcClientDebug(std::move(socket), 1));

    auto rpcSession = RpcSession::make();
    ASSERT_TRUE(rpcSession->setupInetClient("127.0.0.1", port));
    auto rpcBinder = rpcSession->getRootObject();
    ASSERT_NE(nullptr, rpcBinder);

    ASSERT_EQ(OK, rpcBinder->pingBinder());

    ASSERT_EQ(String16(), rpcBinder->getInterfaceDescriptor());
    ASSERT_EQ(OK, rpcBinder->pingBinder());
}
