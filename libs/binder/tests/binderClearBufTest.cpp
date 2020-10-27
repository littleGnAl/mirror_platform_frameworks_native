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

#include <binder/Binder.h>
#include <binder/IBinder.h>
#include <binder/IPCThreadState.h>
#include <binder/IServiceManager.h>
#include <binder/Parcel.h>
#include <binder/Stability.h>
#include <android-base/logging.h>

#include <sys/prctl.h>
#include <thread>

using namespace android;

const String16 kServerName = String16("binderClearBuf");

std::string hexString(const void* bytes, size_t len) {
    if (bytes == nullptr) return "<null>";

    const uint8_t* bytes8 = static_cast<const uint8_t*>(bytes);
    char chars[] = "0123456789abcdef";
    std::string result;
    result.resize(len * 2);

    for (size_t i = 0; i < len; i++) {
        result[2 * i] = chars[bytes8[i] >> 4];
        result[2 * i + 1] = chars[bytes8[i] & 0xf];
    }

    return result;
}

class FooBar : public BBinder {
 public:
    enum {
        TRANSACTION_REPEAT_STRING = IBinder::FIRST_CALL_TRANSACTION,
        TRANSACTION_GET_LAST = TRANSACTION_REPEAT_STRING + 1,
    };

    std::mutex foo;
    std::string last;

    status_t onTransact(uint32_t code, const Parcel& data, Parcel* reply, uint32_t flags) {
        const uint8_t* lastData = data.mData;
        size_t lastDataSize = data.mDataSize;

        switch (code) {
            case TRANSACTION_REPEAT_STRING: {
                const char* str = data.readCString();
                foo.lock();
                LOG(ERROR) << "in asdfasdf foobar " << this << " " << (void*)lastData << " " << lastDataSize;
                std::thread([=] {
                    LOG(ERROR) << "out asdfasdf foobar " << this << " " << (void*)lastData << " " << lastDataSize;
                    sleep(1);
                    this->last = hexString(lastData, lastDataSize);
                    foo.unlock();
                }).detach();
                return reply->writeCString(str == nullptr ? "<null>" : str);
            }
            case TRANSACTION_GET_LAST: {
                foo.lock();
                auto ret = reply->writeCString(last.c_str());
                foo.unlock();
                return ret;
            }
        }
        return BBinder::onTransact(code, data, reply, flags);
    }
    static std::string GetLast(const sp<IBinder> binder) {
        Parcel reply;
        binder->transact(TRANSACTION_GET_LAST, {}, &reply, 0);
        return reply.readCString();
    }
    static std::string RepeatString(const sp<IBinder> binder, const std::string& repeat) {
        Parcel data;
        data.writeCString(repeat.c_str());
        std::string result;
        const uint8_t* lastReply;
        size_t lastReplySize;
        {
            Parcel reply;
            binder->transact(TRANSACTION_REPEAT_STRING, data, &reply, FLAG_CLEAR_BUF);
            result = reply.readCString();
            lastReply = reply.mData;
            lastReplySize = reply.mDataSize;
        }
        IPCThreadState::self()->flushCommands();
        sleep(1);
        std::cout << "Reply data: " << hexString(lastReply, lastReplySize) << std::endl;
        return result;
    }
};

int main() {
    std::cout << "parent pid: " <<  getpid() << std::endl;
    auto fork_pid = fork();
    if (fork_pid == 0) {
        // child process
        prctl(PR_SET_PDEATHSIG, SIGHUP);

        sp<IBinder> server = new FooBar;
        android::defaultServiceManager()->addService(kServerName, server);

        IPCThreadState::self()->joinThreadPool(true);
        exit(1);  // should not reach
    }
    std::cout << "child pid: " << fork_pid << std::endl;

    // This is not racey. Just giving these services some time to register before we call
    // getService which sleeps for much longer...
    usleep(10000);

    sp<IBinder> binder = defaultServiceManager()->getService(kServerName);
    CHECK(binder != nullptr);

    std::string result = FooBar::RepeatString(binder, "foo");
    std::cout << "Returned: " << result << std::endl;

    sleep(2);
    std::cout << "Data parcel in kernel '" << FooBar::GetLast(binder) << "'" << std::endl;

    return 0;
}
