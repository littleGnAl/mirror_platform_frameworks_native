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
#include <thread>
#include <vector>

#include <android-base/endian.h>
#include <android-base/logging.h>
#include <android-base/macros.h>
#include <android-base/unique_fd.h>
#include <adbwifi/pairing/pairing_auth.h>
#include <adb/ssl/tls_connection.h>

#include "pairing.pb.h"

namespace adbwifi {
namespace pairing {

using namespace adb;
using android::base::unique_fd;

namespace {
class PairingConnectionImpl : public PairingConnection {
public:
    explicit PairingConnectionImpl(Role role,
                                   const Data& pswd,
                                   const PeerInfo& peer_info,
                                   const Data& certificate,
                                   const Data& priv_key);
    virtual ~PairingConnectionImpl();

    virtual bool start(int fd, ResultCallback cb, void* opaque) override;

private:
    // Setup the tls connection.
    bool setupTlsConnection(int fd);

    /************ PairingPacketHeader methods ****************/
    // Tries to write out the header and payload.
    bool writeHeader(const PairingPacketHeader* header, std::string_view payload);
    // Tries to parse incoming data into the |header|. Returns true if header
    // is valid and header version is supported. |header| is filled on success.
    // |header| may contain garbage if unsuccessful.
    bool readHeader(PairingPacketHeader* header);
    // Creates a PairingPacketHeader.
    void createHeader(PairingPacketHeader* header,
                      adb::proto::PairingPacket::Type type,
                      uint32_t payload_size);
    // Checks if actual matches expected.
    bool checkHeaderType(adb::proto::PairingPacket::Type expected, uint8_t actual);

    /*********** State related methods **************/
    // Handles the State::ExchangingMsgs state.
    bool doExchangeMsgs();
    // Handles the State::ExchangingPeerInfo state.
    bool doExchangePeerInfo();

    // The background task to do the pairing.
    void startWorker();

    // Calls |cb_| and sets the state to Stopped.
    void notifyResult(const PeerInfo* p);

    enum class State {
        Ready,
        ExchangingMsgs,
        ExchangingPeerInfo,
        Stopped,
    };

    std::atomic<State> state_{State::Ready};
    Role role_;
    Data pswd_;
    PeerInfo peer_info_;
    Data cert_;
    Data priv_key_;

    // Peer's info
    PeerInfo their_info_;

    ResultCallback cb_;
    void* opaque_ = nullptr;
    std::unique_ptr<ssl::TlsConnection> tls_;
    std::unique_ptr<PairingAuth> auth_;
    unique_fd fd_;
    std::thread thread_;
};  // class PairingConnectionImpl

PairingConnectionImpl::PairingConnectionImpl(Role role,
                                             const Data& pswd,
                                             const PeerInfo& peer_info,
                                             const Data& cert,
                                             const Data& priv_key) :
        role_(role),
        pswd_(pswd),
        peer_info_(peer_info),
        cert_(cert),
        priv_key_(priv_key) {
    CHECK(!pswd_.empty() &&
          !cert_.empty() &&
          !priv_key_.empty());

    switch (role_) {
    case Role::Client:
        auth_ = PairingAuth::create(PairingAuth::Role::Client, pswd);
        break;
    case Role::Server:
        auth_ = PairingAuth::create(PairingAuth::Role::Server, pswd);
        break;
    }
}

PairingConnectionImpl::~PairingConnectionImpl() {
    // Force close the fd and wait for the worker thread to finish.
    fd_.reset();
    if (thread_.joinable()) {
        thread_.join();
    }
}

bool PairingConnectionImpl::setupTlsConnection(int fd) {
    switch (role_) {
    case Role::Server:
        tls_ = ssl::TlsConnection::create(ssl::TlsConnection::Role::Server,
                std::string_view(reinterpret_cast<const char*>(cert_.data()), cert_.size()),
                std::string_view(reinterpret_cast<const char*>(priv_key_.data()), priv_key_.size()));
        break;
    case Role::Client:
        tls_ = ssl::TlsConnection::create(ssl::TlsConnection::Role::Client,
                std::string_view(reinterpret_cast<const char*>(cert_.data()), cert_.size()),
                std::string_view(reinterpret_cast<const char*>(priv_key_.data()), priv_key_.size()));
        break;
    }

    if (tls_ == nullptr) {
        LOG(ERROR) << "Unable to start TlsConnection. Unable to pair fd=" << fd;
        return false;
    }

    // Turn off certificate verification
    tls_->enableCertificateVerification(false);

    // SSL doesn't seem to behave correctly with fdevents so just do a blocking
    // read for the pairing data.
    if (!tls_->doHandshake(fd)) {
        LOG(ERROR) << "Failed to handshake with the peer fd=" << fd;
        return false;
    }

    return true;
}

bool PairingConnectionImpl::writeHeader(const PairingPacketHeader* header,
                                        std::string_view payload) {
    PairingPacketHeader network_header = *header;
    network_header.payload = htonl(network_header.payload);
    if (!tls_->writeFully(std::string_view(reinterpret_cast<const char*>(&network_header), sizeof(PairingPacketHeader))) ||
        !tls_->writeFully(payload)) {
        LOG(ERROR) << "Failed to write out PairingPacketHeader";
        state_ = State::Stopped;
        return false;
    }
    return true;
}

bool PairingConnectionImpl::readHeader(PairingPacketHeader* header) {
    auto data = tls_->readFully(sizeof(PairingPacketHeader));
    if (data.empty()) {
        return false;
    }

    uint8_t* p = data.data();
    // First byte is always PairingPacketHeader version
    header->version = *p;
    ++p;
    if (header->version < kMinSupportedKeyHeaderVersion ||
        header->version > kMaxSupportedKeyHeaderVersion) {
        LOG(ERROR) << "PairingPacketHeader version mismatch (us=" << kCurrentKeyHeaderVersion
                   << " them=" << header->version << ")";
        return false;
    }
    // Next byte is the PairingPacket::Type
    if (!adb::proto::PairingPacket::Type_IsValid(*p)) {
        LOG(ERROR) << "Unknown PairingPacket type=" << static_cast<uint32_t>(*p);
        return false;
    }
    header->type = *p;
    ++p;
    // Last, the payload size
    header->payload = ntohl(*(reinterpret_cast<uint32_t*>(p)));
    if (header->payload == 0 ||
        header->payload > kMaxPayloadSize) {
        LOG(ERROR) << "header payload not within a safe payload size (size="
                   << header->payload << ")";
        return false;
    }

    return true;
}

void PairingConnectionImpl::createHeader(PairingPacketHeader* header,
                                         adb::proto::PairingPacket::Type type,
                                         uint32_t payload_size) {
    header->version = kCurrentKeyHeaderVersion;
    uint8_t type8 = static_cast<uint8_t>(static_cast<int>(type));
    header->type = type8;
    header->payload = payload_size;
}

bool PairingConnectionImpl::checkHeaderType(adb::proto::PairingPacket::Type expected_type,
                                            uint8_t actual) {
        uint8_t expected = *reinterpret_cast<uint8_t*>(&expected_type);
        if (actual != expected) {
            LOG(ERROR) << "Unexpected header type (expected=" << static_cast<uint32_t>(expected)
                       << " actual=" << static_cast<uint32_t>(actual) << ")";
            return false;
        }
        return true;
}

void PairingConnectionImpl::notifyResult(const PeerInfo* p) {
      cb_(p, opaque_);
      state_ = State::Stopped;
}

bool PairingConnectionImpl::start(int fd,
                                  ResultCallback cb,
                                  void* opaque) {
    if (fd < 0) {
        return false;
    }

    State expected = State::Ready;
    if (!state_.compare_exchange_strong(expected, State::ExchangingMsgs)) {
        return false;
    }

    fd_.reset(fd);
    cb_ = cb;
    opaque_ = opaque;

    thread_ = std::thread([this] { startWorker(); });
    return true;
}

bool PairingConnectionImpl::doExchangeMsgs() {
    PairingPacketHeader header;
    createHeader(&header,
                 adb::proto::PairingPacket::SPAKE2_MSG,
                 auth_->msg().size());

    // Write our SPAKE2 msg
    auto msg = std::string_view(reinterpret_cast<const char*>(auth_->msg().data()),
                                auth_->msg().size());
    if (!writeHeader(&header, msg)) {
        LOG(ERROR) << "Failed to write SPAKE2 msg.";
        return false;
    }

    // Read the peer's SPAKE2 msg header
    if (!readHeader(&header)) {
        LOG(ERROR) << "Invalid PairingPacketHeader.";
        notifyResult(nullptr);
        return false;
    }
    if (!checkHeaderType(adb::proto::PairingPacket::SPAKE2_MSG,
                         header.type)) {
        return false;
    }

    // Read the SPAKE2 msg payload and initialize the cipher for
    // encrypting the PeerInfo and certificate.
    auto their_msg = tls_->readFully(header.payload);
    if (their_msg.empty() || !auth_->initCipher(their_msg)) {
        LOG(ERROR) << "Unable to initialize pairing cipher [their_msg.size="
                   << their_msg.size() << "]";
        return false;
    }

    return true;
}

bool PairingConnectionImpl::doExchangePeerInfo() {
    // Encrypt PeerInfo
    std::vector<uint8_t> buf;
    uint8_t* p = reinterpret_cast<uint8_t*>(&peer_info_);
    buf.assign(p, p + sizeof(peer_info_));
    buf = auth_->encrypt(buf);
    if (buf.empty()) {
        LOG(ERROR) << "Failed to encrypt certificate";
        return false;
    }

    // Write out the packet header
    PairingPacketHeader out_header;
    out_header.version = kCurrentKeyHeaderVersion;
    out_header.type = static_cast<uint8_t>(static_cast<int>(adb::proto::PairingPacket::PEER_INFO));
    out_header.payload = htonl(buf.size());
    if (!tls_->writeFully(std::string_view(reinterpret_cast<const char*>(&out_header),
                                           sizeof(out_header)))) {
        LOG(ERROR) << "Unable to write PairingPacketHeader";
        return false;
    }

    // Write out the encrypted payload
    if (!tls_->writeFully(std::string_view(reinterpret_cast<const char*>(buf.data()),
                                           buf.size()))) {
        LOG(ERROR) << "Unable to write encrypted certificate";
        return false;
    }

    // Read in the peer's packet header
    PairingPacketHeader header;
    if (!readHeader(&header)) {
        LOG(ERROR) << "Invalid PairingPacketHeader.";
        return false;
    }

    if (!checkHeaderType(adb::proto::PairingPacket::PEER_INFO,
                         header.type)) {
        return false;
    }

    // Read in the encrypted peer certificate
    buf = tls_->readFully(header.payload);
    if (buf.empty()) {
        return false;
    }
    // Try to decrypt the certificate
    buf = auth_->decrypt(buf);
    if (buf.empty()) {
        return false;
    }

    // The decrypted message should contain the PeerInfo.
    p = buf.data();
    ::memcpy(&their_info_, p, sizeof(PeerInfo));
    p += sizeof(PeerInfo);
    // Make sure everything is null-terminated, as all of these fields are
    // supposed to be plain-text strings.
    their_info_.info[kMaxPayloadSize - 1] = '\0';

    return true;
}

void PairingConnectionImpl::startWorker() {
    // Setup the secure transport
    if (!setupTlsConnection(fd_.get())) {
        notifyResult(nullptr);
        return;
    }

    for (;;) {
        switch (state_) {
        case State::ExchangingMsgs:
            if (!doExchangeMsgs()) {
                notifyResult(nullptr);
                return;
            }
            state_ = State::ExchangingPeerInfo;
            break;
        case State::ExchangingPeerInfo:
            if (!doExchangePeerInfo()) {
                notifyResult(nullptr);
                return;
            }
            notifyResult(&their_info_);
            return;
        case State::Ready:
        case State::Stopped:
            LOG(FATAL) << __func__ << ": Got invalid state";
            return;
        }
    }
}

}  // namespace

using Data = PairingConnection::Data;
using Role = PairingConnection::Role;

// static
std::unique_ptr<PairingConnection> PairingConnection::create(Role role,
                                                             const Data& pswd,
                                                             const PeerInfo& peer_info,
                                                             const Data& certificate,
                                                             const Data& priv_key) {
    if (pswd.empty() ||
        certificate.empty() ||
        priv_key.empty()) {
        return nullptr;
    }
    // Make sure peer_info has a non-empty, null-terminated string for info.
    CHECK_EQ('\0', peer_info.info[kMaxPayloadSize - 1]);
    CHECK_GT(strlen(peer_info.info), 0u);
    return std::unique_ptr<PairingConnection>(
            new PairingConnectionImpl(role, pswd, peer_info, certificate, priv_key));
}

}  // namespace pairing
}  // namespace adb
