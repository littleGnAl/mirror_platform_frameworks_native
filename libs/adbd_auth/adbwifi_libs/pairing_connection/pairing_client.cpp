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
#include <adbwifi/fdevent/fdevent.h>
#include <adbwifi/sysdeps/sysdeps.h>

#include "internal/pairing_fdevent.h"

namespace adbwifi {
namespace pairing {

using android::base::unique_fd;

namespace {

class PairingClientImpl : public PairingClient {
public:
    virtual ~PairingClientImpl();

    explicit PairingClientImpl(const Data& pswd,
                               const PeerInfo& peer_info,
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

private:
    // Setup and start the PairingConnection
    bool startConnection();

    enum class State {
        Ready,
        Running,
        Stopped,
    };

    State state_ = State::Ready;
    Data pswd_;
    PeerInfo peer_info_;
    Data cert_;
    Data priv_key_;
    std::string host_;
    int port_ = -1;

    std::unique_ptr<PairingConnection> connection_;
    PairingConnection::ResultCallback cb_;
    void* opaque_ = nullptr;
};  // PairingClientImpl

PairingClientImpl::PairingClientImpl(const Data& pswd,
                                     const PeerInfo& peer_info,
                                     const Data& cert,
                                     const Data& priv_key,
                                     std::string_view host,
                                     int port) :
        pswd_(pswd),
        peer_info_(peer_info),
        cert_(cert),
        priv_key_(priv_key),
        host_(host),
        port_(port) {
    CHECK(!pswd_.empty() &&
          !cert_.empty() &&
          !priv_key_.empty() &&
          !host_.empty() &&
          port > 0);
    CHECK('\0' == peer_info.name[kPeerNameLength - 1] &&
          '\0' == peer_info.guid[kPeerGuidLength - 1] &&
          strlen(peer_info.name) > 0 &&
          strlen(peer_info.guid) > 0);

    state_ = State::Ready;
}

PairingClientImpl::~PairingClientImpl() {
    // Make sure to kill the PairingConnection before terminating the fdevent
    // looper.
    if (connection_ != nullptr) {
        connection_.reset();
    }
}

bool PairingClientImpl::start(PairingConnection::ResultCallback cb,
                              void* opaque) {
    cb_ = cb;
    opaque_ = opaque;

    if (state_ != State::Ready) {
        LOG(ERROR) << "PairingClient already running or finished";
        return false;
    }

    if (!startConnection()) {
        LOG(ERROR) << "Unable to start PairingClient connection";
        state_ = State::Stopped;
        return false;
    }

    state_ = State::Running;
    return true;
}

bool PairingClientImpl::startConnection() {
    std::string err;
    const int timeout = 10; // seconds
    unique_fd fd(sysdeps::network_connect(host_, port_, SOCK_STREAM, timeout, &err));
    if (fd.get() == -1) {
        LOG(ERROR) << "Failed to start pairing connection client ["
                   << err <<"]";
        return false;
    }
    sysdeps::disable_tcp_nagle(fd.get());

    connection_ = PairingConnection::create(PairingConnection::Role::Client,
                                            pswd_,
                                            peer_info_,
                                            cert_,
                                            priv_key_);
    if (connection_ == nullptr) {
        LOG(ERROR) << "PairingClient unable to create a PairingConnection";
        return false;
    }

    if (!connection_->start(fd.release(), cb_, opaque_)) {
        LOG(ERROR) << "PairingClient failed to start the PairingConnection";
        state_ = State::Stopped;
        return false;
    }

    LOG(INFO) << "PairingClient is running";
    return true;
}

}  // namespace

// static
std::unique_ptr<PairingClient> PairingClient::create(const Data& pswd,
                                                     const PeerInfo& peer_info,
                                                     const Data& cert,
                                                     const Data& priv_key,
                                                     std::string_view ip_addr) {
    if (pswd.empty() || cert.empty() ||
        priv_key.empty() || ip_addr.empty()) {
        return nullptr;
    }
    // Make sure peer_info has a non-empty, null-terminated string for guid and
    // name.
    if ('\0' != peer_info.name[kPeerNameLength - 1] ||
        '\0' != peer_info.guid[kPeerGuidLength - 1] ||
        strlen(peer_info.name) == 0 ||
        strlen(peer_info.guid) == 0) {
        LOG(ERROR) << "The GUID/short name fields are empty or not null-terminated";
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

    // Start the fdevent loop if not started yet.
    internal::start_fdevent_loop_thread();

    if (port <= 0) {
        LOG(INFO) << "Using default pairing port=" << kDefaultPairingPort;
        port = kDefaultPairingPort;
    }

    // Make sure we don't use any other port.
    if (port != kDefaultPairingPort) {
        LOG(WARNING) << "Using non-default pairing port=" << port;
    }

    return std::unique_ptr<PairingClient>(
            new PairingClientImpl(pswd, peer_info, cert, priv_key, host, port));
}

}  // namespace pairing
}  // namespace adbwifi
