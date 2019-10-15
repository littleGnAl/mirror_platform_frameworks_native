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

#include "adbwifi/pairing/pairing_server.h"

#include <atomic>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <thread>
#include <unordered_map>
#include <vector>

#include <android-base/logging.h>
#include <android-base/parsenetaddress.h>
#include <android-base/thread_annotations.h>
#include <android-base/unique_fd.h>
#include <adbwifi/fdevent/fdevent.h>
#include <adbwifi/sysdeps/sysdeps.h>

#include "adbwifi/pairing/pairing_connection.h"

namespace adbwifi {
namespace pairing {

using android::base::unique_fd;

namespace {

class PairingServerImpl : public PairingServer {
public:
    virtual ~PairingServerImpl();

    // All parameters must be non-empty.
    explicit PairingServerImpl(const Data& pswd,
                               const Data& cert,
                               const Data& priv_key,
                               int port);

    // Starts the pairing server. This call is non-blocking. Upon completion,
    // if the pairing was successful, then |cb| will be called with the PublicKeyHeader
    // containing the info of the trusted peer. Otherwise, |cb| will be
    // called with an empty value. Start can only be called once in the lifetime
    // of this object.
    //
    // Returns true if PairingServer was successfully started. Otherwise,
    // returns false.
    virtual bool start(PairingConnection::ResultCallback cb, void* opaque) override;

    // Cancels the pairing connection.
    virtual void stop() override;

private:
    // =====  fdevent related methods =====
    // Start the fdevent loop on a separate thread. This will block until
    // we know for sure the fdevent_loop is running.
    void startFdeventLoop();
    // Waits for fdevent loop to process a no-op. This call guarantees that all
    // prior fdevent_run_on_main_thread() calls have been executed.
    void waitForFdeventLoop();
    // Terminates the fdevent loop and waits for the thread to exit.
    void terminateFdeventLoopAndWait();

    // Setup the server socket to accept incoming connections
    bool setupServer();

    // fdevent callback
    static void staticOnFdEvent(int fd, unsigned ev, void* data);
    // handles a new pairing client connection
    bool handleNewClientConnection(int fd);

    enum class State {
        Ready,
        Running,
        Stopped,
    };
    State state_ = State::Ready;
    Data pswd_;
    Data cert_;
    Data priv_key_;
    int port_ = -1;

    PairingConnection::ResultCallback cb_;
    void* opaque_ = nullptr;
    std::thread thread_;

    std::thread fdevent_thread_;
    fdevent::fdevent* server_fde_ = nullptr;

    using ConnectionPtr = std::unique_ptr<PairingConnection>;
    std::unordered_map<int, ConnectionPtr> mConnections;
    static constexpr int kMaxConnections = 10;
};  // PairingServerImpl

PairingServerImpl::PairingServerImpl(const Data& pswd,
                                     const Data& cert,
                                     const Data& priv_key,
                                     int port) :
        pswd_(pswd),
        cert_(cert),
        priv_key_(priv_key),
        port_(port) {
    CHECK(!pswd_.empty() &&
          !cert_.empty() &&
          !priv_key_.empty() &&
          port_ > 0);
}

PairingServerImpl::~PairingServerImpl() {
    stop();
}

void PairingServerImpl::startFdeventLoop() {
    fdevent_thread_ = std::thread([]() { fdevent::fdevent_loop(); });
    waitForFdeventLoop();
}

void PairingServerImpl::waitForFdeventLoop() {
    std::mutex mutex;
    std::condition_variable cv;

    fdevent::fdevent_run_on_main_thread([&]() {
        std::lock_guard<std::mutex> lock(mutex);
        cv.notify_one();
    });

    std::unique_lock<std::mutex> lock(mutex);
    cv.wait(lock);
}

void PairingServerImpl::terminateFdeventLoopAndWait() {
    if (!fdevent_thread_.joinable()) {
        return;
    }

    fdevent::fdevent_terminate_loop();
    fdevent_thread_.join();
}

bool PairingServerImpl::start(PairingConnection::ResultCallback cb,
                                  void* opaque) {
    cb_ = cb;
    opaque_ = opaque;

    if (state_ != State::Ready) {
        LOG(ERROR) << "PairingServer already running or stopped";
        return false;
    }

    startFdeventLoop();
    if (!setupServer()) {
        LOG(ERROR) << "Unable to start PairingServer";
        state_ = State::Stopped;
        return false;
    }

    state_ = State::Running;
    return true;
}

void PairingServerImpl::stop() {
    if (state_ != State::Running) {
        return;
    }

    // Break the socket connection and wait.
    if (thread_.joinable()) {
        thread_.join();
    }
    // Stop the fdevent loop.
    terminateFdeventLoopAndWait();
    state_ = State::Stopped;
}

bool PairingServerImpl::setupServer() {
    std::string err;
    unique_fd fd(sysdeps::network_inaddr_any_server(port_, SOCK_STREAM, &err));
    if (fd.get() == -1) {
        LOG(ERROR) << "Failed to start pairing connection server ["
                   << err <<"]";
        return false;
    }
    sysdeps::close_on_exec(fd.get());

    fdevent::fdevent_run_on_main_thread([&]() {
        server_fde_ = fdevent::fdevent_create(fd.release(),
                                              &PairingServerImpl::staticOnFdEvent,
                                              this);

    });
    waitForFdeventLoop();

    if (server_fde_ == nullptr) {
        LOG(ERROR) << "Unable to create fdevent for adbwifi pairing server";
        return false;
    }

    LOG(INFO) << "Created fdevent for adbwifi pairing server";
    return true;
}

// static
void PairingServerImpl::staticOnFdEvent(int fd, unsigned ev, void* data) {
    LOG(INFO) << "Got server fdevent";
    if (data == nullptr) {
        LOG(ERROR) << "server pointer is null";
        return;
    }
    auto server = reinterpret_cast<PairingServerImpl*>(data);
    if (fd != server->server_fde_->fd.get()) {
        LOG(ERROR) << "fd=" << fd << " doesn't match connectionfd="
                   << server->server_fde_->fd.get();
        return;
    }
    if ((ev & FDE_READ) == 0) {
        server->handleNewClientConnection(fd);
    }
}

bool PairingServerImpl::handleNewClientConnection(int fd) {
    LOG(INFO) << "Accepting a new pairing connection fd=" << fd;
    int client_fd = sysdeps::adb_socket_accept(fd, nullptr, nullptr);
    if (client_fd == -1) {
        PLOG(WARNING) << "adb_socket_accept failed fd=" << fd;
        return false;
    }

    if (mConnections.size() >= kMaxConnections) {
        LOG(WARNING) << "Unable to accept new pairing client connection. "
                     << "At max number of connections ("<< kMaxConnections << ")";
        sysdeps::adb_close(client_fd);
        return false;
    }

    // TODO: make a PairingConnection
    auto connection = PairingConnection::create(PairingConnection::Role::Server,
                                                {0x01},
                                                {0x01},
                                                {0x01});
    return true;
}

}  // namespace

// static
std::unique_ptr<PairingServer> PairingServer::create(const Data& pswd,
                                                     const Data& cert,
                                                     const Data& priv_key,
                                                     int port) {
    if (pswd.empty() || cert.empty() || priv_key.empty()) {
        return nullptr;
    }
    return std::unique_ptr<PairingServer>(
            new PairingServerImpl(pswd, cert, priv_key, port));
}

}  // namespace pairing
}  // namespace adbwifi
