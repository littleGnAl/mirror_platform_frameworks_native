/*
 * Copyright (C) 2017 The Android Open Source Project
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

#define LOG_TAG "Lshal"
#include <android-base/logging.h>

#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <android/hardware/tests/baz/1.0/IQuux.h>
#include <hidl/HidlTransportSupport.h>
#include <vintf/parse_xml.h>

#include "ListCommand.h"
#include "Lshal.h"

#define NELEMS(array)   static_cast<int>(sizeof(array) / sizeof(array[0]))

using namespace testing;

using ::android::hidl::base::V1_0::DebugInfo;
using ::android::hidl::base::V1_0::IBase;
using ::android::hidl::manager::V1_0::IServiceManager;
using ::android::hidl::manager::V1_0::IServiceNotification;
using ::android::hardware::hidl_death_recipient;
using ::android::hardware::hidl_handle;
using ::android::hardware::hidl_string;
using ::android::hardware::hidl_vec;

using InstanceDebugInfo = IServiceManager::InstanceDebugInfo;

namespace android {
namespace hardware {
namespace tests {
namespace baz {
namespace V1_0 {
namespace implementation {
struct Quux : android::hardware::tests::baz::V1_0::IQuux {
    ::android::hardware::Return<void> debug(const hidl_handle& hh, const hidl_vec<hidl_string>& options) override {
        const native_handle_t *handle = hh.getNativeHandle();
        if (handle->numFds < 1) {
            return Void();
        }
        int fd = handle->data[0];
        std::string content{descriptor};
        for (const auto &option : options) {
            content += "\n";
            content += option.c_str();
        }
        ssize_t written = write(fd, content.c_str(), content.size());
        if (written != (ssize_t)content.size()) {
            LOG(WARNING) << "SERVER(Quux) debug writes " << written << " bytes < "
                    << content.size() << " bytes, errno = " << errno;
        }
        return Void();
    }
};

} // namespace implementation
} // namespace V1_0
} // namespace baz
} // namespace tests
} // namespace hardware

namespace lshal {

class MockServiceManager : public IServiceManager {
public:
    template<typename T>
    using R = ::android::hardware::Return<T>;
    using String = const hidl_string&;
    ~MockServiceManager() = default;

#define MOCK_METHOD_CB(name) MOCK_METHOD1(name, R<void>(IServiceManager::name##_cb))

    MOCK_METHOD2(get, R<sp<IBase>>(String, String));
    MOCK_METHOD2(add, R<bool>(String, const sp<IBase>&));
    MOCK_METHOD2(getTransport, R<IServiceManager::Transport>(String, String));
    MOCK_METHOD_CB(list);
    MOCK_METHOD2(listByInterface, R<void>(String, listByInterface_cb));
    MOCK_METHOD3(registerForNotifications, R<bool>(String, String, const sp<IServiceNotification>&));
    MOCK_METHOD_CB(debugDump);
    MOCK_METHOD2(registerPassthroughClient, R<void>(String, String));
    MOCK_METHOD_CB(interfaceChain);
    MOCK_METHOD2(debug, R<void>(const hidl_handle&, const hidl_vec<hidl_string>&));
    MOCK_METHOD_CB(interfaceDescriptor);
    MOCK_METHOD_CB(getHashChain);
    MOCK_METHOD0(setHalInstrumentation, R<void>());
    MOCK_METHOD2(linkToDeath, R<bool>(const sp<hidl_death_recipient>&, uint64_t));
    MOCK_METHOD0(ping, R<void>());
    MOCK_METHOD_CB(getDebugInfo);
    MOCK_METHOD0(notifySyspropsChanged, R<void>());
    MOCK_METHOD1(unlinkToDeath, R<bool>(const sp<hidl_death_recipient>&));

};

class DebugTest : public ::testing::Test {
public:
    void SetUp() override {
        using ::android::hardware::tests::baz::V1_0::IQuux;
        using ::android::hardware::tests::baz::V1_0::implementation::Quux;

        err.str("");
        out.str("");
        serviceManager = new testing::NiceMock<MockServiceManager>();
        ON_CALL(*serviceManager, get(_, _)).WillByDefault(Invoke(
            [](const auto &iface, const auto &inst) -> ::android::hardware::Return<sp<IBase>> {
                if (iface == IQuux::descriptor && inst == "default")
                    return new Quux();
                return nullptr;
            }));

        lshal = std::make_unique<Lshal>(out, err, serviceManager, serviceManager);
    }
    void TearDown() override {}

    std::stringstream err;
    std::stringstream out;
    sp<MockServiceManager> serviceManager;

    std::unique_ptr<Lshal> lshal;
};

static Arg createArg(const std::vector<const char*>& args) {
    return Arg{static_cast<int>(args.size()), const_cast<char**>(args.data())};
}

template<typename T>
static Status callMain(const std::unique_ptr<T>& lshal, const std::vector<const char*>& args) {
    return lshal->main(createArg(args));
}

TEST_F(DebugTest, Debug) {
    EXPECT_EQ(0u, callMain(lshal, {
        "lshal", "debug", "android.hardware.tests.baz@1.0::IQuux/default", "foo", "bar"
    }));
    EXPECT_THAT(out.str(), StrEq("android.hardware.tests.baz@1.0::IQuux\nfoo\nbar"));
    EXPECT_THAT(err.str(), IsEmpty());
}

TEST_F(DebugTest, Debug2) {
    EXPECT_EQ(0u, callMain(lshal, {
        "lshal", "debug", "android.hardware.tests.baz@1.0::IQuux", "baz", "quux"
    }));
    EXPECT_THAT(out.str(), StrEq("android.hardware.tests.baz@1.0::IQuux\nbaz\nquux"));
    EXPECT_THAT(err.str(), IsEmpty());
}

TEST_F(DebugTest, Debug3) {
    EXPECT_NE(0u, callMain(lshal, {
        "lshal", "debug", "android.hardware.tests.doesnotexist@1.0::IDoesNotExist",
    }));
    EXPECT_THAT(err.str(), HasSubstr("does not exist"));
}

class MockLshal : public Lshal {
public:
    MockLshal() {}
    ~MockLshal() = default;
    MOCK_CONST_METHOD0(out, NullableOStream<std::ostream>());
    MOCK_CONST_METHOD0(err, NullableOStream<std::ostream>());
};

// expose protected fields and methods for ListCommand
class MockListCommand : public ListCommand {
public:
    MockListCommand(Lshal* lshal) : ListCommand(*lshal) {}

    bool isEmitDebugInfo() const { return mEmitDebugInfo; }
    bool isDumpVintf() const { return mVintf; }
    bool isNeat() const { return mNeat; }
    Status parseArgs(const Arg& arg) { return ListCommand::parseArgs("", arg); }
    void forEachTable(const std::function<void(const Table &)> &f) const {
        return ListCommand::forEachTable(f);
    }
    Status fetch() { return ListCommand::fetch(); }
    void dumpVintf(const NullableOStream<std::ostream>& out) {
        return ListCommand::dumpVintf(out);
    }

    MOCK_CONST_METHOD2(getPidInfo, bool(pid_t, PidInfo*));
    MOCK_CONST_METHOD1(parseCmdline, std::string(pid_t));
};

class ListParseArgsTest : public ::testing::Test {
public:
    void SetUp() override {
        mockLshal = std::make_unique<NiceMock<MockLshal>>();
        mockList = std::make_unique<MockListCommand>(mockLshal.get());
        // ListCommand::parseArgs should parse arguments from the second element
        optind = 1;
    }
    std::unique_ptr<MockLshal> mockLshal;
    std::unique_ptr<MockListCommand> mockList;
    std::stringstream output;
};

TEST_F(ListParseArgsTest, Default) {
    // default args
    EXPECT_EQ(0u, mockList->parseArgs(createArg({})));
    mockList->forEachTable([](const Table& table) {
        EXPECT_EQ(SelectedColumns({TableColumnType::INTERFACE_NAME, TableColumnType::THREADS,
                                   TableColumnType::SERVER_PID, TableColumnType::CLIENT_PIDS}),
                  table.getSelectedColumns());
    });
    EXPECT_EQ(false, mockList->isEmitDebugInfo());
    EXPECT_EQ(false, mockList->isDumpVintf());
    EXPECT_EQ(false, mockList->isNeat());
}

TEST_F(ListParseArgsTest, Args) {
    EXPECT_EQ(0u, mockList->parseArgs(createArg({"lshal", "-p", "-i", "-a", "-c"})));
    mockList->forEachTable([](const Table& table) {
        EXPECT_EQ(SelectedColumns({TableColumnType::SERVER_PID, TableColumnType::INTERFACE_NAME,
                                   TableColumnType::SERVER_ADDR, TableColumnType::CLIENT_PIDS}),
                  table.getSelectedColumns());
    });
}

TEST_F(ListParseArgsTest, Cmds) {
    EXPECT_EQ(0u, mockList->parseArgs(createArg({"lshal", "-m"})));
    mockList->forEachTable([](const Table& table) {
        EXPECT_EQ(SelectedColumns({TableColumnType::INTERFACE_NAME, TableColumnType::THREADS,
                                   TableColumnType::SERVER_CMD, TableColumnType::CLIENT_CMDS}),
                  table.getSelectedColumns());
    });
}

TEST_F(ListParseArgsTest, Debug) {
    EXPECT_EQ(0u, mockList->parseArgs(createArg({"lshal", "-d"})));
    EXPECT_EQ(true, mockList->isEmitDebugInfo());
}

TEST_F(ListParseArgsTest, Neat) {
    EXPECT_EQ(0u, mockList->parseArgs(createArg({"lshal", "--neat"})));
    EXPECT_EQ(true, mockList->isNeat());
}

TEST_F(ListParseArgsTest, Vintf) {
    EXPECT_EQ(0u, mockList->parseArgs(createArg({"lshal", "--init-vintf"})));
    EXPECT_EQ(true, mockList->isDumpVintf());
}

TEST_F(ListParseArgsTest, DebugAndNeat) {
    ON_CALL(*mockLshal, err()).WillByDefault(Return(NullableOStream<std::ostream>(output)));
    EXPECT_NE(0u, mockList->parseArgs(createArg({"lshal", "--neat", "-d"})));
    EXPECT_THAT(output.str(), StrNe(""));
}

/// Fetch Test

// A set of deterministic functions to generate fake debug infos.
static uint64_t getPtr(pid_t serverId) { return 10000 + serverId; }
static std::vector<pid_t> getClients(pid_t serverId) {
    return {serverId + 1, serverId + 3};
}
static PidInfo getPidInfoFromId(pid_t serverId) {
    PidInfo info;
    info.refPids[getPtr(serverId)] = getClients(serverId);
    info.threadUsage = 10 + serverId;
    info.threadCount = 20 + serverId;
    return info;
}
static std::string getInterfaceName(pid_t serverId) {
    return "a.h.foo" + std::to_string(serverId) + "@" + std::to_string(serverId) + ".0::IFoo";
}
static std::string getInstanceName(pid_t serverId) {
    return std::to_string(serverId);
}
static pid_t getIdFromInstanceName(const hidl_string& instance) {
    return atoi(instance.c_str());
}
static std::string getFqInstanceName(pid_t serverId) {
    return getInterfaceName(serverId) + "/" + getInstanceName(serverId);
}
static std::string getCmdlineFromId(pid_t serverId) {
    return "command_line_" + std::to_string(serverId);
}

// Fake service returned by mocked IServiceManager::get.
class TestService : public IBase {
public:
    TestService(DebugInfo&& info) : mInfo(std::move(info)) {}
    hardware::Return<void> getDebugInfo(getDebugInfo_cb cb) override {
        cb(mInfo);
        return hardware::Void();
    }
private:
    DebugInfo mInfo;
};

class ListFetchTest : public ::testing::Test {
public:
    void SetUp() override {
        serviceManager = new testing::NiceMock<MockServiceManager>();
        passthruManager = new testing::NiceMock<MockServiceManager>();
        lshal = std::make_unique<Lshal>(out, err, serviceManager, passthruManager);
        mockList = std::make_unique<NiceMock<MockListCommand>>(lshal.get());

        initMockList();
        initMockServiceManager();
    }

    void initMockList() {
        ON_CALL(*mockList, getPidInfo(_,_)).WillByDefault(Invoke(
            [](pid_t serverPid, PidInfo* info) {
                *info = getPidInfoFromId(serverPid);
                return true;
            }));
        ON_CALL(*mockList, parseCmdline(_)).WillByDefault(Invoke(&getCmdlineFromId));
    }

    void initMockServiceManager() {
        using A = DebugInfo::Architecture;
        ON_CALL(*serviceManager, list(_)).WillByDefault(Invoke(
            [] (IServiceManager::list_cb cb) {
                cb({ getFqInstanceName(1), getFqInstanceName(2) });
                return hardware::Void();
            }));

        ON_CALL(*serviceManager, get(_, _)).WillByDefault(Invoke(
            [&](const hidl_string&, const hidl_string& instance) {
                int id = getIdFromInstanceName(instance);
                return sp<IBase>(new TestService({ id /* pid */, getPtr(id), A::IS_64BIT }));
            }));

        ON_CALL(*serviceManager, debugDump(_)).WillByDefault(Invoke(
            [] (IServiceManager::debugDump_cb cb) {
                cb({InstanceDebugInfo{getInterfaceName(3), getInstanceName(3), 3,
                                      getClients(3), A::IS_32BIT},
                    InstanceDebugInfo{getInterfaceName(4), getInstanceName(4), 4,
                                      getClients(4), A::IS_32BIT}});
                return hardware::Void();
            }));

        ON_CALL(*passthruManager, debugDump(_)).WillByDefault(Invoke(
            [] (IServiceManager::debugDump_cb cb) {
                cb({InstanceDebugInfo{getInterfaceName(5), getInstanceName(5), 5,
                                      getClients(5), A::IS_32BIT},
                    InstanceDebugInfo{getInterfaceName(6), getInstanceName(6), 6,
                                      getClients(6), A::IS_32BIT}});
                return hardware::Void();
            }));
    }

    std::stringstream err;
    std::stringstream out;
    std::unique_ptr<Lshal> lshal;
    std::unique_ptr<MockListCommand> mockList;
    sp<MockServiceManager> serviceManager;
    sp<MockServiceManager> passthruManager;
};

TEST_F(ListFetchTest, Fetch) {
    EXPECT_EQ(0u, mockList->fetch());
    std::array<std::string, 6> transports{{"hwbinder", "hwbinder", "passthrough",
                                          "passthrough", "passthrough", "passthrough"}};
    std::array<Architecture, 6> archs{{ARCH64, ARCH64, ARCH32, ARCH32, ARCH32, ARCH32}};
    int id = 1;
    mockList->forEachTable([&](const Table& table) {
        ASSERT_EQ(2u, table.size());
        for (const auto& entry : table) {
            const auto& transport = transports[id - 1];
            TableEntry expected{
                .interfaceName = getFqInstanceName(id),
                .transport = transport,
                .serverPid = transport == "hwbinder" ? id : NO_PID,
                .threadUsage = transport == "hwbinder" ? getPidInfoFromId(id).threadUsage : 0,
                .threadCount = transport == "hwbinder" ? getPidInfoFromId(id).threadCount : 0,
                .serverCmdline = {},
                .serverObjectAddress = transport == "hwbinder" ? getPtr(id) : NO_PTR,
                .clientPids = getClients(id),
                .clientCmdlines = {},
                .arch = archs[id - 1],
            };
            EXPECT_EQ(expected, entry) << expected.to_string() << " vs. " << entry.to_string();

            ++id;
        }
    });

}

TEST_F(ListFetchTest, DumpVintf) {
    const std::string xml =
        "<!-- \n"
        "    This is a skeleton device manifest. Notes: \n"
        "    1. android.hidl.*, android.frameworks.*, android.system.* are not included.\n"
        "    2. If a HAL is supported in both hwbinder and passthrough transport, \n"
        "       only hwbinder is shown.\n"
        "    3. It is likely that HALs in passthrough transport does not have\n"
        "       <interface> declared; users will have to write them by hand.\n"
        "    4. A HAL with lower minor version can be overridden by a HAL with\n"
        "       higher minor version if they have the same name and major version.\n"
        "    5. sepolicy version is set to 0.0. It is recommended that the entry\n"
        "       is removed from the manifest file and written by assemble_vintf\n"
        "       at build time.\n"
        "-->\n"
        "<manifest version=\"1.0\" type=\"device\">\n"
        "    <hal format=\"hidl\">\n"
        "        <name>a.h.foo1</name>\n"
        "        <transport>hwbinder</transport>\n"
        "        <version>1.0</version>\n"
        "        <interface>\n"
        "            <name>IFoo</name>\n"
        "            <instance>1</instance>\n"
        "        </interface>\n"
        "    </hal>\n"
        "    <hal format=\"hidl\">\n"
        "        <name>a.h.foo2</name>\n"
        "        <transport>hwbinder</transport>\n"
        "        <version>2.0</version>\n"
        "        <interface>\n"
        "            <name>IFoo</name>\n"
        "            <instance>2</instance>\n"
        "        </interface>\n"
        "    </hal>\n"
        "    <hal format=\"hidl\">\n"
        "        <name>a.h.foo3</name>\n"
        "        <transport arch=\"32\">passthrough</transport>\n"
        "        <version>3.0</version>\n"
        "        <interface>\n"
        "            <name>IFoo</name>\n"
        "            <instance>3</instance>\n"
        "        </interface>\n"
        "    </hal>\n"
        "    <hal format=\"hidl\">\n"
        "        <name>a.h.foo4</name>\n"
        "        <transport arch=\"32\">passthrough</transport>\n"
        "        <version>4.0</version>\n"
        "        <interface>\n"
        "            <name>IFoo</name>\n"
        "            <instance>4</instance>\n"
        "        </interface>\n"
        "    </hal>\n"
        "    <hal format=\"hidl\">\n"
        "        <name>a.h.foo5</name>\n"
        "        <transport arch=\"32\">passthrough</transport>\n"
        "        <version>5.0</version>\n"
        "    </hal>\n"
        "    <hal format=\"hidl\">\n"
        "        <name>a.h.foo6</name>\n"
        "        <transport arch=\"32\">passthrough</transport>\n"
        "        <version>6.0</version>\n"
        "    </hal>\n"
        "    <sepolicy>\n"
        "        <version>0.0</version>\n"
        "    </sepolicy>\n"
        "</manifest>\n";
    EXPECT_EQ(0u, mockList->fetch());
    std::stringstream ss;
    mockList->dumpVintf(ss);
    EXPECT_EQ(xml, ss.str());

    vintf::HalManifest m;
    EXPECT_EQ(true, vintf::gHalManifestConverter(&m, ss.str()))
        << "--init-vintf does not emit valid HAL manifest: "
        << vintf::gHalManifestConverter.lastError();
}

} // namespace lshal
} // namespace android

int main(int argc, char **argv) {
    ::testing::InitGoogleMock(&argc, argv);
    return RUN_ALL_TESTS();
}
