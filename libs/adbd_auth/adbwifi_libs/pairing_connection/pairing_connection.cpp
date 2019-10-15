/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
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

#include "adbwifi/pairing/pairing_connection.h"

#include <atomic>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <thread>
#include <vector>

#include <android-base/logging.h>
#include <android-base/parsenetaddress.h>
#include <android-base/thread_annotations.h>
#include <android-base/unique_fd.h>
#include <adbwifi/sysdeps/sysdeps.h>

using android::base::unique_fd;

namespace adbwifi {
namespace pairing {

namespace {

constexpr int kPairingPort = 51393;

class PairingConnectionImpl : public PairingConnection {
public:
    virtual ~PairingConnectionImpl();

    explicit PairingConnectionImpl(Role role,
                                   const Data& pswd,
                                   const Data& cert,
                                   std::string_view ip_addr);

    // Starts the pairing connection. This call spawns another thread to handle
    // the pairing. Upon completion, if the pairing was successful,
    // then |cb| will be called with the certificate. Otherwise, |cb| will be
    // called with an empty value.
    //
    // Pairing is successful if both server/client uses the same non-empty
    // |pswd|, and they are able to exchange the information. |pswd| and
    // |certificate| must be non-empty. start() can only be called once in the
    // lifetime of this object.
    virtual bool start(ResultCallback cb, void* opaque) override;

    // Cancels the pairing connection.
    virtual void stop() EXCLUDES(mutex_) override;

    // Waits for the start() thread to finish.
    virtual void wait() EXCLUDES(mutex_) override;

    // If the connection is invalid, then the object is useless and should be
    // destroyed.
    bool isValid();

private:
    // The worker function for the start() method. Called on a separate thread.
    void startWorker() EXCLUDES(mutex_);
    // Sends condition variable notify to unblock wait().
    void notify() EXCLUDES(mutex_);
    // Setup the server connection
    bool setupServer(unique_fd& fd) EXCLUDES(mutex_);

    enum class State {
        Invalid,
        Ready,
        Running,
        ReadingMsg,
        ReadingCertificate,
        Done,
    };
    std::atomic<State> state_{State::Invalid};
    Role role_;
    Data pswd_;
    Data cert_;
    std::string host_;
    int port_ = kPairingPort;

    ResultCallback cb_;
    void* opaque_ = nullptr;
    std::thread thread_;
    std::mutex mutex_;
    std::condition_variable cv_;
};  // PairingConnectionImpl

PairingConnectionImpl::PairingConnectionImpl(Role role,
                                             const Data& pswd,
                                             const Data& cert,
                                             std::string_view ip_addr) :
        role_(role),
        pswd_(pswd),
        cert_(cert) {
    if (pswd_.empty() || cert_.empty()) {
        LOG(ERROR) << "Password/certificate cannot be empty.";
        return;
    }

    if (role_ == Role::Client) {
        if (ip_addr.empty()) {
            LOG(ERROR) << "Ip address cannot be empty for Role::Client";
            return;
        }
        std::string err;
        if (!android::base::ParseNetAddress(std::string(ip_addr),
                                            &host_,
                                            &port_,
                                            nullptr,
                                            &err)) {
            LOG(ERROR) << "Bad host address [" << err << "]";
            return;
        }
        // Make sure we don't use any other port.
        if (port_ != kPairingPort) {
            LOG(ERROR) << "User-defined ports are not supported.";
            return;
        }
    }

    state_ = State::Ready;
}

PairingConnectionImpl::~PairingConnectionImpl() {
    stop();
}

bool PairingConnectionImpl::isValid() {
    std::lock_guard<std::mutex> lock(mutex_);
    return state_ != State::Invalid;
}

bool PairingConnectionImpl::start(PairingConnection::ResultCallback cb,
                                  void* opaque) {
    cb_ = cb;
    opaque_ = opaque;

    auto expected = State::Ready;
    if (!state_.compare_exchange_strong(expected, State::Running)) {
        LOG(ERROR) << "PairingConnection already running";
        return false;
    }

    thread_ = std::thread([this]() {
        startWorker();
    });
    return true;
}

void PairingConnectionImpl::stop() {
    // Break the socket connection and wait.
    if (thread_.joinable()) {
        thread_.join();
    }
}

void PairingConnectionImpl::wait() {
    LOG(INFO) << "Waiting for pairing to complete";
    if (state_ != State::Ready &&
        state_ != State::Done) {
        std::unique_lock<std::mutex> lock(mutex_);
        cv_.wait(lock);
    }
    LOG(INFO) << "pairing completed";
}

void PairingConnectionImpl::notify() {
    std::lock_guard<std::mutex> lock(mutex_);
    cv_.notify_all();
}

bool PairingConnectionImpl::setupServer(unique_fd& fd) {
    std::string err;
    fd.reset(sysdeps::network_inaddr_any_server(port_, SOCK_STREAM, &err));
    if (fd.get() == -1) {
        LOG(ERROR) << "Failed to start pairing connection server ["
                   << err <<"]";
        return false;
    }
    // TODO: setup fdevent

    return true;
}

void PairingConnectionImpl::startWorker() {
    LOG(INFO) << "PairingConnection starting";
    Data peer_cert;
    unique_fd fd;

    // Try to connect/accept
    switch (role_) {
    case Role::Server: {
        if (!setupServer(fd)) {
            notify();
            return;
        }
        break;
    }
    case Role::Client:
        break;
    }

    // TODO: read the certificate
    peer_cert = Data{0x01};
    cb_(peer_cert, opaque_);

    state_ = State::Done;
    notify();
}

}  // namespace

// static
std::unique_ptr<PairingConnection> PairingConnection::create(Role role,
                                                             const Data& pswd,
                                                             const Data& cert,
                                                             std::string_view ip_addr) {
    auto* p = new PairingConnectionImpl(role, pswd, cert, ip_addr);
    if (!p->isValid()) {
        delete p;
        return nullptr;
    }
    return std::unique_ptr<PairingConnection>(p);
}

}  // namespace pairing
}  // namespace adbwifi
