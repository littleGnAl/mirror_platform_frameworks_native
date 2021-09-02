#include <android-base/file.h>
#include <android-base/logging.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/RpcServer.h>
#include <binder/RpcSession.h>
#include <gtest/gtest.h>
#include <signal.h>
#include <unistd.h>
#include "BnBinderDefaultImplTest.h"
#include "BnBinderDefaultInner.h"
#include "BpBinderDefaultImplTest.h"
#include "IBinderDefaultImplTest.h"

namespace android {
static constexpr char kInstanceName[] = "default.impl.test";
static constexpr char kAddress[] = "/myAddress2";
class LocalBinderDefault : public BnBinderDefaultImplTest {
public:
    ::android::binder::Status returnIBar(::android::sp<::IBinderDefaultInner>*) override {
        return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
    }
    ::android::binder::Status returnHalf(int32_t, int32_t*) override {
        LOG(INFO) << "Local returnHalf";
        return ::android::binder::Status::fromStatusT(::android::UNKNOWN_TRANSACTION);
    }
};

class LocalBinderDefaultInner : public BnBinderDefaultInner {};

class RemoteBinderDefault : public BnBinderDefaultImplTest {
    ::android::binder::Status returnIBar(::android::sp<::IBinderDefaultInner>*) override {
        return ::android::binder::Status::ok();
    }
    ::android::binder::Status returnHalf(int32_t in, int32_t* out) override {
        *out = in / 2;
        LOG(INFO) << "Remote returnHalf";
        return ::android::binder::Status::ok();
    }
};

class RemoteBinderDefaultInner : public BnBinderDefaultInner {};

class DefaultImplTest : public ::testing::Test {};

std::string getAddress() {
    std::string tmp = getenv("TMPDIR") ?: "/tmp";
    return tmp + kAddress;
}

void doShimThings() {
    auto session = RpcSession::make();
    while (OK != session->setupUnixDomainClient(getAddress().c_str())) {
        sleep(1);
    }
    LOG(INFO) << "Success shim connected to remote";
    auto proxyBinder = sp<BpBinderDefaultImplTest>::make(sp<LocalBinderDefault>::make());
    auto defaultImpl = std::make_unique<BpBinderDefaultImplTest>(session->getRootObject());
    proxyBinder->setDefaultImpl(std::move(defaultImpl));
    auto status = defaultServiceManager()->addService(String16(kInstanceName),
                                                      IInterface::asBinder(proxyBinder));
    if (status != OK) {
        LOG(INFO) << "Failed shim to register local binder! " << status;
    } else {
        LOG(INFO) << "Success shim regiserted local binder!";
    }
    // sanity check to make sure remote call in the default impl works
    int result = 0;
    interface_cast<IBinderDefaultImplTest>(session->getRootObject())->returnHalf(4, &result);
    CHECK(result == 2) << "Failed returnHalf sanity check";
    result = 0;
    proxyBinder->returnHalf(4, &result);
    CHECK(result == 2) << "Failed returnHalf defautlImpl sanity check";

    IPCThreadState::self()->joinThreadPool();
}

void doRemoteHalThings() {
    auto server = RpcServer::make();
    auto remoteBinder = new RemoteBinderDefault();
    server->setRootObject(remoteBinder);
    server->iUnderstandThisCodeIsExperimentalAndIWillNotUseItInProduction();

    if (OK != server->setupUnixDomainServer(getAddress().c_str())) {
        LOG(ERROR) << "Failed to set up remote server";
    } else {
        LOG(INFO) << "Success set up remote server";
        server->join();
        (void)server->shutdown();
    }
}

void doClientThings() {
    auto service = waitForService<IBinderDefaultImplTest>(String16(kInstanceName));
    if (service) {
        LOG(INFO) << "Success client got service!";
        int result = 0;
        auto ret = service->returnHalf(4, &result);
        EXPECT_EQ(2, result);
    } else {
        LOG(INFO) << "Failed to get service in client!";
    }
}

TEST(DefaultImplTest, LocalBinder) {
    pid_t shim = fork();
    pid_t remoteHal = 0;
    if (shim == 0) {
        doShimThings();
    } else {
        remoteHal = fork();
        if (remoteHal == 0) {
            doRemoteHalThings();
        } else {
            doClientThings();
        }
    }
    // The domain socket still registers as in use unless I delete it through
    // adb... I think I need to shutdown the server somehow
    // base::RemoveFileIfExists(getAddress());
    kill(shim, SIGTERM);
    kill(remoteHal, SIGTERM);
}
} // namespace android
