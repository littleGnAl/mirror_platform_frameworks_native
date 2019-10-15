/*
 * Copyright (C) 2019 The Android Open Source Project
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

#include "adbwifi/pairing/pairing_client.h"

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


namespace adbwifi {
namespace pairing {

using android::base::unique_fd;

namespace {

class PairingClientImpl : public PairingClient {
public:
    virtual ~PairingClientImpl();

    explicit PairingClientImpl(const Data& pswd,
                               const Data& cert,
                               const Data& priv_key,
                               std::string_view host,
                               int port);

    // Starts the pairing client. This call is non-blocking. Upon pairing
    // completion, |cb| will be called with the PeerInfo on success,
    // or an empty value on failure.
    //
    // Returns true if PairingClient was successfully started. Otherwise,
    // return false.
    virtual bool start(PairingConnection::ResultCallback cb, void* opaque) override;

    // Cancels the pairing connection.
    virtual void stop() override;

private:
    // Setup the client connection
    bool setupClient();

    enum class State {
        Ready,
        Running,
        Stopped,
    };

    State state_ = State::Ready;
    Data pswd_;
    Data cert_;
    Data priv_key_;
    std::string host_;
    int port_ = -1;

    PairingConnection::ResultCallback cb_;
    void* opaque_ = nullptr;
};  // PairingClientImpl

PairingClientImpl::PairingClientImpl(const Data& pswd,
                                     const Data& cert,
                                     const Data& priv_key,
                                     std::string_view host,
                                     int port) :
        pswd_(pswd),
        cert_(cert),
        priv_key_(priv_key),
        host_(host),
        port_(port) {
    CHECK(!pswd_.empty() &&
          !cert_.empty() &&
          !priv_key_.empty() &&
          !host_.empty() &&
          port > 0);

    state_ = State::Ready;
}

PairingClientImpl::~PairingClientImpl() {
    stop();
}

bool PairingClientImpl::start(PairingConnection::ResultCallback cb,
                              void* opaque) {
    cb_ = cb;
    opaque_ = opaque;

    if (state_ != State::Ready) {
        LOG(ERROR) << "PairingClient already running or finished";
        return false;
    }

    if (!setupClient()) {
        LOG(ERROR) << "Unable to start PairingClient connection";
        state_ = State::Stopped;
        return false;
    }

    state_ = State::Running;
    return true;
}

void PairingClientImpl::stop() {
    // TODO: break the PairingConnection.
}

bool PairingClientImpl::setupClient() {
    std::string err;
    const int timeout = 10; // seconds
    unique_fd fd(sysdeps::network_connect(host_, port_, SOCK_STREAM, timeout, &err));
    if (fd.get() == -1) {
        LOG(ERROR) << "Failed to start pairing connection client ["
                   << err <<"]";
        return false;
    }
    sysdeps::disable_tcp_nagle(fd.get());

    // TODO: setup PairingConnection

    LOG(INFO) << "PairingClient is running";
    return true;
}

}  // namespace

// static
std::unique_ptr<PairingClient> PairingClient::create(const Data& pswd,
                                                     const Data& cert,
                                                     const Data& priv_key,
                                                     std::string_view ip_addr) {
    if (pswd.empty() || cert.empty() ||
        priv_key.empty() || ip_addr.empty()) {
        return nullptr;
    }

    // Try to parse the host address
    std::string err;
    std::string host;
    int port = -1;
    if (!android::base::ParseNetAddress(std::string(ip_addr),
                                        &host,
                                        &port,
                                        nullptr,
                                        &err)) {
        LOG(ERROR) << "Bad host address [" << err << "]";
        return nullptr;
    }

    // Make sure we don't use any other port.
    if (port != kDefaultPairingPort) {
        LOG(WARNING) << "Using non-default pairing port number=" << port;
    }

    return std::unique_ptr<PairingClient>(
            new PairingClientImpl(pswd, cert, priv_key, host, port));
}

}  // namespace pairing
}  // namespace adbwifi
