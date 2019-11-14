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

#include "adbwifi/crypto/key_store.h"


#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include <fstream>
#include <thread>
#include <unordered_map>
#include <vector>

#include <adbwifi/sysdeps/sysdeps.h>
#include <android-base/endian.h>
#include <android-base/file.h>
#include <android-base/logging.h>
#include <openssl/ec_key.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "adbwifi/crypto/device_identifier.h"
#include "proto/key_store.pb.h"

namespace adbwifi {
namespace crypto {

namespace {
const char kKeyStoreName[] = "adb_wifi_keys";
const char kPrivateKeyName[] = "adb_system_key.pem";
const char kPublicKeyName[] = "adb_system_cert.pem";

const char kBasicConstraints[] = "critical,CA:TRUE";
// RSA certificates require the "keyEncipherment" usage,
// non-RSA certificates require the "digitalSignature" usage.
// We currently only use EC_KEYs, so just hardcode in the "digitalsignature" for
// now.
const char kKeyUsage[] = "critical,keyCertSign,cRLSign,digitalSignature";
const char kSubjectKeyIdentifier[] = "hash";

constexpr int kCurveName = NID_X9_62_prime256v1;
constexpr int kCertLifetimeSeconds = 10 * 365 * 24 * 60 * 60;

class KeyStoreImpl : public KeyStore {
public:
    explicit KeyStoreImpl(std::string_view keystore_path);

    virtual DeviceInfo getDeviceInfo() const override;
    virtual bool storePeerInfo(const PeerInfo& info) override;
    virtual bool removePeerInfo(const std::string& guid) override;
    virtual PeerInfo getPeerInfo(std::string_view guid) override;
    virtual size_t size() const override { return keys_.size(); };
    virtual std::pair<std::string, PeerInfo> operator[](const size_t idx) const override;

    // Tries to read or create the keystore if one doesn't exist.
    // Returns true if successful, false otherwise.
    bool init();

    const std::string& getKeyStorePath() const;
    const std::string& getSysPrivKeyPath() const;
    const std::string& getSysPubKeyPath() const;

private:
    bool generateSystemCertificate();
    bool readSystemCertificate();
    bool readKeyStoreFromFile(adbwifi::proto::KeyStore& key_store,
                              std::unordered_map<std::string, adbwifi::proto::Key>& keys);
    bool writeKeyStoreToFile(std::unordered_map<std::string, adbwifi::proto::Key>& keys);

    std::unordered_map<std::string, adbwifi::proto::Key> keys_;
    std::string priv_key_;
    std::string cert_;

    std::string keystore_path_;
    std::string keystore_file_;
    std::string priv_key_file_;
    std::string pub_key_file_;

    std::unique_ptr<DeviceIdentifier> device_id_;
    adbwifi::proto::KeyStore key_store_;
};

KeyStoreImpl::KeyStoreImpl(std::string_view keystore_path) :
    keystore_path_(keystore_path) {
    device_id_.reset(new DeviceIdentifier(keystore_path_));
    keystore_file_ = keystore_path_ + OS_PATH_SEPARATOR + kKeyStoreName;
    priv_key_file_ = keystore_path_ + OS_PATH_SEPARATOR + kPrivateKeyName;
    pub_key_file_ = keystore_path_ + OS_PATH_SEPARATOR + kPublicKeyName;
}

bool KeyStoreImpl::init() {
    if (device_id_->getUniqueDeviceId().empty()) {
        return false;
    }
    if (!readSystemCertificate()) {
        if (!generateSystemCertificate()) {
            return false;
        }
        // Read the certificate we just generated again, they were only stored
        // on disk.
        if (!readSystemCertificate()) {
            return false;
        }
    }
    return readKeyStoreFromFile(key_store_, keys_);
}

KeyStore::DeviceInfo KeyStoreImpl::getDeviceInfo() const {
    if (!device_id_->getUniqueDeviceId().empty() &&
        !device_id_->getDeviceName().empty() &&
        !cert_.empty() &&
        !priv_key_.empty()) {
        return std::make_tuple(device_id_->getUniqueDeviceId(),
                               device_id_->getDeviceName(),
                               cert_, priv_key_);
    }
    return std::nullopt;
}

bool KeyStoreImpl::removePeerInfo(const std::string& guid) {
    if (guid.empty()) {
        return false;
    }
    auto foundkey = keys_.find(guid);
    if (foundkey != keys_.end()) {
        keys_.erase(foundkey);
        if (!writeKeyStoreToFile(keys_)) {
            LOG(WARNING) << "Unable to remove " << guid << " from keystore";
            return false;
        }
        return true;
    }
    return false;
}

bool KeyStoreImpl::storePeerInfo(const PeerInfo& info) {
    if (!info.has_value()) {
        return false;
    }
    auto [guid, name, cert] = *info;
    adbwifi::proto::Key key;
    key.set_guid(guid);
    key.set_name(name);
    key.set_certificate(cert);

    // If this guid already exists in the map, replace it.
    auto foundkey = keys_.find(guid);
    if (foundkey != keys_.end()) {
        keys_.erase(foundkey);
    }
    keys_[guid] = key;

    if (!writeKeyStoreToFile(keys_)) {
        LOG(ERROR) << "Unable to write public key store";
        keys_.erase(guid);
        return false;
    }
    return true;

}

KeyStore::PeerInfo KeyStoreImpl::getPeerInfo(std::string_view guid) {
    auto it = keys_.find(std::string(guid));
    if (it == keys_.end()) {
        return std::nullopt;
    }
    return std::make_tuple(it->second.guid(), it->second.name(), it->second.certificate());
}

std::pair<std::string, KeyStore::PeerInfo> KeyStoreImpl::operator[](const size_t idx) const {
    auto it = keys_.begin();
    std::advance(it, idx);
    const adbwifi::proto::Key& key = it->second;
    return std::pair<std::string, PeerInfo>(it->first,
                                            std::make_tuple(key.guid(), key.name(), key.certificate()));
}

static bool add_ext(X509* cert, int nid, const char* value) {
    size_t len = strlen(value) + 1;
    std::vector<char> mutableValue(value, value + len);
    X509V3_CTX context;

    X509V3_set_ctx_nodb(&context);

    X509V3_set_ctx(&context, cert, cert, nullptr, nullptr, 0);
    X509_EXTENSION* ex = X509V3_EXT_nconf_nid(nullptr, &context, nid,
                                              mutableValue.data());
    if (!ex) {
        return false;
    }

    X509_add_ext(cert, ex, -1);
    X509_EXTENSION_free(ex);
    return true;
}

bool KeyStoreImpl::generateSystemCertificate() {
    bssl::UniquePtr<EVP_PKEY> evpKey(EVP_PKEY_new());
    if (!evpKey) {
        LOG(ERROR) << "Failed to create private/public key container";
        return false;
    }

    bssl::UniquePtr<EC_KEY> ecKey(EC_KEY_new_by_curve_name(kCurveName));
    if (!ecKey) {
        LOG(ERROR) << "Unable to create EC key";
        return false;
    }
    EC_KEY_set_asn1_flag(ecKey.get(), OPENSSL_EC_NAMED_CURVE);
    if (!EC_KEY_generate_key(ecKey.get())) {
        LOG(ERROR) << "Unable to generate EC key";
        return false;
    }

    if (!EVP_PKEY_assign_EC_KEY(evpKey.get(), ecKey.release())) {
        LOG(ERROR) << "Unable to assign EC key";
        return false;
    }

    bssl::UniquePtr<X509> x509(X509_new());
    if (!x509) {
        LOG(ERROR) << "Unable to allocate x509 container";
        return false;
    }
    X509_set_version(x509.get(), 2);

    ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 1);
    X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(x509.get()), kCertLifetimeSeconds);

    if (!X509_set_pubkey(x509.get(), evpKey.get())) {
        LOG(ERROR) << "Unable to set x509 public key";
        return false;
    }

    X509_NAME* name = X509_get_subject_name(x509.get());
    if (!name) {
        LOG(ERROR) << "Unable to get x509 subject name";
        return false;
    }
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("US"),
                               -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>("Android"),
                               -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char*>(device_id_->getUniqueDeviceId().c_str()),
                               -1, -1, 0);
    if (!X509_set_issuer_name(x509.get(), name)) {
        LOG(ERROR) << "Unable to set x509 issuer name";
        return false;
    }

    add_ext(x509.get(), NID_basic_constraints, kBasicConstraints);
    add_ext(x509.get(), NID_key_usage, kKeyUsage);
    add_ext(x509.get(), NID_subject_key_identifier, kSubjectKeyIdentifier);

    int bytes = X509_sign(x509.get(), evpKey.get(), EVP_sha256());
    if (bytes <= 0) {
        LOG(ERROR) << "Unable to sign x509 certificate";
        return false;
    }

    std::unique_ptr<FILE, decltype(&fclose)> file(nullptr, &fclose);
    file.reset(fopen(getSysPrivKeyPath().c_str(), "wb"));
    if (!file) {
        LOG(ERROR) << "Unable to open private system key file for writing: "
                   << strerror(errno);
        return false;
    }
    if (!PEM_write_PKCS8PrivateKey(file.get(), evpKey.get(), nullptr, nullptr,
                                   0, nullptr, nullptr)) {
        LOG(ERROR) << "Unable to write private system key: "
                   << strerror(errno);
        return false;
    }

    file.reset(fopen(getSysPubKeyPath().c_str(), "wb"));
    if (!file) {
        LOG(ERROR) << "Unable to open public system key file";
        return false;
    }
    if (!PEM_write_X509(file.get(), x509.get())) {
        LOG(ERROR) << "Unable to write public system key file: "
                   << strerror(errno);
        return false;
    }
    // Set permissions so adbd can read it later.
    chmod(getSysPrivKeyPath().c_str(), S_IRUSR | S_IWUSR | S_IRGRP);
    chmod(getSysPubKeyPath().c_str(), S_IRUSR | S_IWUSR | S_IRGRP);
    return true;
}

bool KeyStoreImpl::readSystemCertificate() {
    LOG(ERROR) << "Reading system certificate";
    if (!android::base::ReadFileToString(getSysPrivKeyPath(), &priv_key_)) {
        LOG(ERROR) << "Unable to read the private key file";
        return false;
    }

    if (!android::base::ReadFileToString(getSysPubKeyPath(), &cert_)) {
        LOG(ERROR) << "Unable to read the system certificate";
        return false;
    }

    return true;
}

bool KeyStoreImpl::readKeyStoreFromFile(adbwifi::proto::KeyStore& key_store,
                                        std::unordered_map<std::string, adbwifi::proto::Key>& keys) {
    std::string store_name = getKeyStorePath();
    std::ifstream file(store_name, std::ios::binary);
    if (!file) {
        // Not an error. It just means there's no keystore.
        LOG(INFO) << "No adbwifi keystore found.";
        return true;
    }
    // Read the keystore into the protobuf.
    if (!key_store.ParseFromIstream(&file)) {
        // keystore may have been corrupted. Let's just delete it, otherwise
        // we'll never be able to store or read anything again.
        LOG(ERROR) << "adbwifi keystore seems corrupted. Deleting the keystore.";
        sysdeps::adb_unlink(store_name.c_str());
        return false;
    }

    // Read all the saved keys
    for (const auto& key : key_store.keys()) {
        keys[key.guid()] = key;
    }

    return true;
}

bool KeyStoreImpl::writeKeyStoreToFile(std::unordered_map<std::string, adbwifi::proto::Key>& keys) {
    LOG(ERROR) << "Writing public keys";
    std::string storeName = getKeyStorePath();
    std::string tempName = storeName + ".tmp";
    adbwifi::proto::KeyStore key_store;

    // This temp file should be deleted if this method fails so we don't leave
    // this stuff around. Using a temp file allows the previous data to remain
    // intact in this scenario.
    // TODO: This raises the question if it's safer to keep
    // the old data around or if everything should be nuked. If this operation
    // is preceeded by the removal of an untrusted key and this fails then the
    // untrusted key remains. On the other hand adding a new key and then
    // failing to write keys should probably not erase all known keys. We might
    // want to have the writes in these two scenarios behave differently.
    errno = 0;
    std::unique_ptr<TemporaryFile> temp_file(new TemporaryFile(keystore_path_));
    if (temp_file->fd == -1) {
        LOG(ERROR) << "Failed to open keystore file '" << temp_file->path
                   << "' for writing: " << strerror(errno);
        return false;
    }

    // Write out all the saved keys
    for (const auto& id_key : keys) {
        const adbwifi::proto::Key& key = id_key.second;
        auto* pkey = key_store.add_keys();
        pkey->CopyFrom(key);
    }

    if (!key_store.SerializeToFileDescriptor(temp_file->fd)) {
        LOG(ERROR) << "Unable to write key store out.";
        return false;
    }
    temp_file->DoNotRemove();
    std::string temp_file_name(temp_file->path);
    temp_file.reset();

    // Replace the existing key store with the new one.
    std::string toBeDeleted = storeName;
    toBeDeleted += ".tbd";
    if (sysdeps::adb_rename(storeName.c_str(), toBeDeleted.c_str()) != 0) {
        // Don't exit here, this is not necessarily an error, the first time
        // around there is no key store.
        LOG(WARNING) << "Failed to adb_rename old key store";
    }

    if (sysdeps::adb_rename(temp_file_name.c_str(), storeName.c_str()) != 0) {
        LOG(ERROR) << "Failed to replace old key store";
        sysdeps::adb_rename(toBeDeleted.c_str(), storeName.c_str());
        sysdeps::adb_unlink(temp_file_name.c_str());
        return false;
    }

    // Remove the old keystore
    sysdeps::adb_unlink(toBeDeleted.c_str());

    LOG(ERROR) << "Successfully wrote key store";
    key_store_.CopyFrom(key_store);
    chmod(getKeyStorePath().c_str(), S_IRUSR | S_IWUSR | S_IRGRP);

    return true;
}

const std::string& KeyStoreImpl::getKeyStorePath() const {
    return keystore_file_;
}

const std::string& KeyStoreImpl::getSysPrivKeyPath() const {
    return priv_key_file_;
}

const std::string& KeyStoreImpl::getSysPubKeyPath() const {
    return pub_key_file_;
}
}  // namespace

// static
std::unique_ptr<KeyStore> KeyStore::create(std::string_view keystore_path) {
    auto p = new KeyStoreImpl(keystore_path);
    if (!p->init()) {
        LOG(INFO) << "Failed to initialize keystore";
        delete p;
        return nullptr;
    }
    return std::unique_ptr<KeyStore>(p);
}

}  // namespace crypto
}  // namespace adbwifi
