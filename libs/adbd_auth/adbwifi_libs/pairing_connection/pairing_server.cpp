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
#include <deque>
#include <iomanip>
#include <mutex>
#include <sstream>
#include <thread>
#include <tuple>
#include <unordered_map>
#include <variant>
#include <vector>

#include <android-base/logging.h>
#include <android-base/parsenetaddress.h>
#include <android-base/thread_annotations.h>
#include <android-base/unique_fd.h>
#include <adbwifi/fdevent/fdevent.h>
#include <adbwifi/sysdeps/sysdeps.h>

#include "internal/constants.h"
#include "internal/pairing_fdevent.h"
#include "adbwifi/pairing/pairing_connection.h"

namespace adbwifi {
namespace pairing {

using android::base::ScopedLockAssertion;
using android::base::unique_fd;

namespace {

// The implimentation has two background threads running: one to handle and
// accept any new pairing connection requests (socket accept), and the other to
// handle connection events (connection started, connection finished).
class PairingServerImpl : public PairingServer {
public:
    virtual ~PairingServerImpl();

    // All parameters must be non-empty.
    explicit PairingServerImpl(const Data& pswd,
                               const PeerInfo& peer_info,
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

private:
    // Setup the server socket to accept incoming connections
    bool setupServer();

    // ======== fdevent thread ================
    // fdevent callback
    static void staticOnFdEvent(int fd, unsigned ev, void* data);
    // handles a new pairing client connection
    bool handleNewClientConnection(int fd) EXCLUDES(conn_mutex_);

    // ======== connection events thread =============
    std::mutex conn_mutex_;
    std::condition_variable conn_cv_;

    using FdVal = int;
    using ConnectionPtr = std::unique_ptr<PairingConnection>;
    using NewConnectionEvent = std::tuple<unique_fd, ConnectionPtr>;
    // <fd, PeerInfo.name, PeerInfo.guid, certificate>
    using ConnectionFinishedEvent = std::tuple<FdVal,
                                               std::optional<std::string>,
                                               std::optional<std::string>,
                                               std::optional<Data>>;
    using ConnectionEvent = std::variant<NewConnectionEvent,
                                         ConnectionFinishedEvent>;
    // Queue for connections to write into. We have a separate queue to read
    // from, in order to minimize the time the fdevent thread is blocked.
    std::deque<ConnectionEvent> conn_write_queue_ GUARDED_BY(conn_mutex_);
    std::deque<ConnectionEvent> conn_read_queue_;
    // Map of fds to their PairingConnections currently running.
    std::unordered_map<FdVal, ConnectionPtr> connections_;

    void startConnectionEventsThread();

    std::thread conn_events_thread_;
    void connectionEventsWorker();
    bool is_terminate_ GUARDED_BY(conn_mutex_) = false;

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
    int port_ = -1;

    PairingConnection::ResultCallback cb_;
    void* opaque_ = nullptr;
    bool got_valid_pairing_ = false;

    fdevent::fdevent* server_fde_ = nullptr;

};  // PairingServerImpl

PairingServerImpl::PairingServerImpl(const Data& pswd,
                                     const PeerInfo& peer_info,
                                     const Data& cert,
                                     const Data& priv_key,
                                     int port) :
        pswd_(pswd),
        peer_info_(peer_info),
        cert_(cert),
        priv_key_(priv_key),
        port_(port) {
    CHECK(!pswd_.empty() &&
          !cert_.empty() &&
          !priv_key_.empty() &&
          port_ > 0);
    CHECK('\0' == peer_info.name[kPeerNameLength - 1] &&
          '\0' == peer_info.guid[kPeerGuidLength - 1] &&
          strlen(peer_info.name) > 0 &&
          strlen(peer_info.guid) > 0);
}

PairingServerImpl::~PairingServerImpl() {
    // Since these connections have references to us, let's make sure they
    // destruct before us.
    fdevent::fdevent_run_on_main_thread([&]() {
        if (server_fde_ != nullptr) {
            fdevent::fdevent_destroy(server_fde_);
            server_fde_ = nullptr;
        }
    });
    internal::wait_fdevent_loop_thread();

    {
        std::lock_guard<std::mutex> lock(conn_mutex_);
        is_terminate_ = true;
    }
    conn_cv_.notify_one();
    if (conn_events_thread_.joinable()) {
        conn_events_thread_.join();
    }

    // Notify the cb_ if it hasn't already.
    if (!got_valid_pairing_ && cb_ != nullptr) {
        cb_(nullptr, nullptr, opaque_);
    }
}

bool PairingServerImpl::start(PairingConnection::ResultCallback cb,
                              void* opaque) {
    cb_ = cb;
    opaque_ = opaque;

    if (state_ != State::Ready) {
        LOG(ERROR) << "PairingServer already running or stopped";
        return false;
    }

    if (!setupServer()) {
        LOG(ERROR) << "Unable to start PairingServer";
        state_ = State::Stopped;
        return false;
    }

    state_ = State::Running;
    return true;
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
    internal::wait_fdevent_loop_thread();

    if (server_fde_ == nullptr) {
        LOG(ERROR) << "Unable to create fdevent for adbwifi pairing server";
        return false;
    }

    fdevent::fdevent_set(server_fde_, FDE_READ);
    startConnectionEventsThread();

    return true;
}

void PairingServerImpl::startConnectionEventsThread() {
    conn_events_thread_ = std::thread([this]() { connectionEventsWorker(); });
}

void PairingServerImpl::connectionEventsWorker() {
    for (;;) {
        // Transfer the write queue to the read queue.
        {
            std::unique_lock<std::mutex> lock(conn_mutex_);
            ScopedLockAssertion assume_locked(conn_mutex_);

            if (is_terminate_) {
                // We check |is_terminate_| twice because condition_variable's
                // notify() only wakes up a thread if it is in the wait state
                // prior to notify(). Furthermore, we aren't holding the mutex
                // when processing the events in |conn_read_queue_|.
                return;
            }
            if (conn_write_queue_.empty()) {
                // We need to wait for new events, or the termination signal.
                conn_cv_.wait(lock, [this]() REQUIRES(conn_mutex_) { return (is_terminate_ || !conn_write_queue_.empty()); });
            }
            if (is_terminate_) {
                // We're done.
                return;
            }
            // Move all events into the read queue.
            conn_read_queue_ = std::move(conn_write_queue_);
            conn_write_queue_.clear();
        }

        // Process all events in the read queue.
        while (conn_read_queue_.size() > 0) {
            auto& event = conn_read_queue_.front();
            if (auto* p = std::get_if<NewConnectionEvent>(&event)) {
                // Ignore if we are already at the max number of connections
                if (connections_.size() >= internal::kMaxConnections) {
                    conn_read_queue_.pop_front();
                    continue;
                }
                auto [ufd, connection] = std::move(*p);
                int fd = ufd.release();
                bool started = connection->start(
                        fd,
                        [fd](const PeerInfo* peer_info, const Data* cert, void* opaque) {
                            auto* p = reinterpret_cast<PairingServerImpl*>(opaque);

                            ConnectionFinishedEvent event;
                            if (peer_info != nullptr && cert != nullptr) {
                                event = std::make_tuple(fd,
                                                        std::string(peer_info->name),
                                                        std::string(peer_info->guid),
                                                        Data(*cert));
                            } else {
                                event = std::make_tuple(fd, std::nullopt, std::nullopt, std::nullopt);
                            }
                            {
                                std::lock_guard<std::mutex> lock(p->conn_mutex_);
                                p->conn_write_queue_.push_back(std::move(event));
                            }
                            p->conn_cv_.notify_one();

                        },
                        this);
                  if (!started) {
                      LOG(ERROR) << "PairingServer unable to start a PairingConnection fd=" << fd;
                      ufd.reset(fd);
                  } else {
                      connections_[fd] = std::move(connection);
                  }
            } else if (auto* p = std::get_if<ConnectionFinishedEvent>(&event)) {
                auto [fd, name, guid, cert] = std::move(*p);
                if (name.has_value() && guid.has_value() && cert.has_value() &&
                    !name->empty() && !guid->empty() && !cert->empty()) {
                    // Valid pairing. Let's shutdown the server and close any
                    // pairing connections in progress.
                    fdevent::fdevent_run_on_main_thread([&]() {
                        if (server_fde_ != nullptr) {
                            fdevent::fdevent_destroy(server_fde_);
                            server_fde_ = nullptr;
                        }
                    });
                    internal::wait_fdevent_loop_thread();
                    connections_.clear();

                    CHECK_LE(name->size(), kPeerNameLength);
                    CHECK_LE(guid->size(), kPeerGuidLength);
                    PeerInfo info = {};
                    strncpy(info.name, name->data(), name->size());
                    strncpy(info.guid, guid->data(), guid->size());

                    cb_(&info, &*cert, opaque_);

                    got_valid_pairing_ = true;
                    return;
                }
                // Invalid pairing. Close the invalid connection.
                if (connections_.find(fd) != connections_.end()) {
                    connections_.erase(fd);
                }
            }
            conn_read_queue_.pop_front();
        }
    }
}

// static
void PairingServerImpl::staticOnFdEvent(int fd, unsigned ev, void* data) {
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
    if (ev & FDE_READ) {
        server->handleNewClientConnection(fd);
    }
}

bool PairingServerImpl::handleNewClientConnection(int fd) {
    unique_fd ufd(sysdeps::adb_socket_accept(fd, nullptr, nullptr));
    if (ufd == -1) {
        PLOG(WARNING) << "adb_socket_accept failed fd=" << fd;
        return false;
    }
    auto connection = PairingConnection::create(PairingConnection::Role::Server,
                                                pswd_,
                                                peer_info_,
                                                cert_,
                                                priv_key_);
    if (connection == nullptr) {
        LOG(ERROR) << "PairingServer unable to create a PairingConnection fd=" << fd;
        return false;
    }
    // send the new connection to the connection thread for further processing
    NewConnectionEvent event = std::make_tuple(std::move(ufd), std::move(connection));
    {
        std::lock_guard<std::mutex> lock(conn_mutex_);
        conn_write_queue_.push_back(std::move(event));
    }
    conn_cv_.notify_one();

    return true;
}

}  // namespace

// static
std::unique_ptr<PairingServer> PairingServer::create(const Data& pswd,
                                                     const PeerInfo& peer_info,
                                                     const Data& cert,
                                                     const Data& priv_key,
                                                     int port) {
    if (pswd.empty() || cert.empty() || priv_key.empty() || port <= 0) {
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

    // Start the fdevent loop if not started yet.
    internal::start_fdevent_loop_thread();

    if (port != kDefaultPairingPort) {
        LOG(WARNING) << "Starting server with non-default pairing port=" << port;
    }

    return std::unique_ptr<PairingServer>(
            new PairingServerImpl(pswd, peer_info, cert, priv_key, port));
}

}  // namespace pairing
}  // namespace adbwifi
