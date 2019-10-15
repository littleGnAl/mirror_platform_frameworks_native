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

#include "adbwifi/pairing/pairing_connection.h"

#include <stddef.h>
#include <stdint.h>

#include <functional>
#include <memory>
#include <string_view>
#include <vector>

#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/unique_fd.h>

namespace adbwifi {
namespace pairing {

using android::base::unique_fd;

namespace {
class PairingConnectionImpl : public PairingConnection {
public:
    explicit PairingConnectionImpl(Role role,
                                   const Data& pswd,
                                   const Data& certificate,
                                   const Data& priv_key);
    virtual ~PairingConnectionImpl();

    virtual bool start(int fd, ResultCallback cb, void* opaque) override;
    virtual void stop() override;
    virtual void wait() override;

private:
    enum class State {
        Ready,
        Running,
        Stopped,
    };

    State state_ = State::Ready;
    Role role_;
    Data pswd_;
    Data cert_;
    Data priv_key_;

    ResultCallback cb_;
    void* opaque_ = nullptr;
};  // class PairingConnectionImpl

PairingConnectionImpl::PairingConnectionImpl(Role role,
                                             const Data& pswd,
                                             const Data& cert,
                                             const Data& priv_key) :
        role_(role),
        pswd_(pswd),
        cert_(cert),
        priv_key_(priv_key) {
    CHECK(!pswd_.empty() &&
          !cert_.empty() &&
          !priv_key_.empty());
}

PairingConnectionImpl::~PairingConnectionImpl() {
}

bool PairingConnectionImpl::start(int fd,
                                  ResultCallback cb,
                                  void* opaque) {
    // Take ownership of fd
    UNUSED(fd);
    cb_ = cb;
    opaque_ = opaque;

    switch (role_) {
    case Role::Server:
        break;
    case Role::Client:
        break;
    }

    state_ = State::Running;
    return true;
}

void PairingConnectionImpl::stop() {
}

void PairingConnectionImpl::wait() {
}

}  // namespace

using Data = PairingConnection::Data;
using Role = PairingConnection::Role;
// static
std::unique_ptr<PairingConnection> PairingConnection::create(Role role,
                                                             const Data& pswd,
                                                             const Data& certificate,
                                                             const Data& priv_key) {
    if (pswd.empty() ||
        certificate.empty() ||
        priv_key.empty()) {
        return nullptr;
    }

    return std::unique_ptr<PairingConnection>(
            new PairingConnectionImpl(role, pswd, certificate, priv_key));
}

}  // namespace pairing
}  // namespace adbwifi
