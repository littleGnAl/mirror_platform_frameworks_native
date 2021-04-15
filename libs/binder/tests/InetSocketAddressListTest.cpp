#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include "../InetSocketAddressList.h"

using testing::_;
using testing::AllOf;
using testing::ElementsAre;
using testing::Eq;
using testing::InSequence;
using testing::Matcher;
using testing::Property;

namespace android {

using SocketAddress = RpcConnection::SocketAddress;

inline void PrintTo(const SocketAddress& value, std::ostream* os) {
    (*os) << value.toString();
}

namespace {
Matcher<SocketAddress> Match(Matcher<const sockaddr*> addr_matcher,
                             Matcher<std::string> description_matcher) {
    return AllOf(Property(&SocketAddress::addr, addr_matcher),
                 Property(&SocketAddress::toString, description_matcher));
}

void MockFreeAddrInfo(addrinfo*) noexcept {}
} // namespace

class InetSocketAddressListTest : public testing::Test {
public:
    static InetSocketAddressList Make() { return InetSocketAddressList(); }
    static InetSocketAddressList Make(addrinfo* head, std::string_view desc) {
        using AddrInfo = InetSocketAddressList::AddrInfo;
        return InetSocketAddressList(AddrInfo(head, &MockFreeAddrInfo), desc);
    }

private:
};

TEST_F(InetSocketAddressListTest, TestEmptyCtor) {
    EXPECT_THAT(Make(), ElementsAre());
}

TEST_F(InetSocketAddressListTest, TestNull) {
    EXPECT_THAT(Make(nullptr, {}), ElementsAre());
}

TEST_F(InetSocketAddressListTest, TestOne) {
    sockaddr storage{};
    addrinfo ai{
            .ai_addr = &storage,
            .ai_next = nullptr,
    };
    auto list = Make(&ai, "android.com:5");
    EXPECT_THAT(list, ElementsAre(Match(Eq(&storage), Eq("android.com:5"))));
}

TEST_F(InetSocketAddressListTest, TestList) {
    std::vector<sockaddr> storage(5);
    std::vector<addrinfo> addrinfos(storage.size());
    for (size_t i = 0; i < addrinfos.size(); ++i) {
        addrinfos[i] = {
                .ai_addr = &storage[i],
                .ai_next = (i + 1 == addrinfos.size()) ? nullptr : &addrinfos[i + 1],
        };
    }
    auto list = Make(&addrinfos[0], "android.com:100");

    size_t i = 0;
    auto it = list.begin();
    for (; i < addrinfos.size() && it != list.end(); ++i, ++it) {
        EXPECT_THAT(*it, Match(Eq(&storage[i]), Eq("android.com:100")));
    }
    EXPECT_EQ(addrinfos.size(), i)
            << "Size of list is " << i << " != expected size " << addrinfos.size();
    EXPECT_TRUE(it == list.end()) << "Size of list is greater than expected size "
                                  << addrinfos.size();
}

} // namespace android
