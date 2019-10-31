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

#include "crypto/key_store.h"

#include <android-base/endian.h>
#include <android-base/file.h>
#include <android-base/logging.h>

#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include <fstream>
#include <thread>
#include <unordered_map>
#include <vector>

#include <openssl/ec_key.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509v3.h>

#include "compat/msvc-posix.h"
#include "crypto/device_identifier.h"
#include "crypto/ec_key.h"
#include "crypto/proto/key_store.pb.h"
#include "crypto/public_key_header.h"

namespace {
const char kKeyStoreName[] = "adb_wifi_keys";
const char kPrivateKeyName[] = "adb_system_key.pem";
const char kPublicKeyName[] = "adb_system_cert.pem";

const char kBasicConstraints[] = "critical,CA:TRUE";
const char kKeyUsage[] = "critical,keyCertSign,cRLSign";
const char kSubjectKeyIdentifier[] = "hash";

constexpr int kCurveName = NID_X9_62_prime256v1;
constexpr int kCertLifetimeSeconds = 10 * 365 * 24 * 60 * 60;

// A safe estimate on the upper bound of an X.509 certificate.
constexpr uint32_t kMaxX509CertSize = 8192;

std::string sslErrorStr() {
    bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
    ERR_print_errors(bio.get());
    char *buf = nullptr;
    size_t len = BIO_get_mem_data(bio.get(), &buf);
    if (len > 0 && buf) {
        return std::string(buf);
    }
    return "[no error]";
}

// A helper class that opens a file and unless the file is explicitly closed it
// will be deleted in the destructor of this class.
class SelfDestructingFile {
public:
    SelfDestructingFile(const char* path, std::ios_base::openmode mode)
        : file_(path, mode), path_(path) {
    }
    ~SelfDestructingFile() {
        if (file_) {
            file_.close();
            my_unlink(path_.c_str());
        }
    }

    std::ofstream* get() { return &file_; }

    void closeAndDisarm() {
        if (file_) {
            file_.close();
        }
    }

    explicit operator bool() const {
        return !!file_;
    }

    bool operator !() const {
        return !file_;
    }

private:
    std::ofstream file_;
    std::string path_;
};

class KeyStore {
public:
    explicit KeyStore(std::string_view keystore_path);
    // Tries to read or create the keystore if one doesn't exist.
    // Returns true if successful, false otherwise.
    bool init();

    // Get the system's public key if one exists, if it does not exist nullptr
    // is returned.
    Key* getSystemPublicKey(KeyType type = KeyType::EllipticCurve);

    // Store the |public_key| of another system.
    bool storePublicKey(const PublicKeyHeader* header,
                        const char* public_key);

    // Get the public |key|, |name| and |type| associated with the device/system
    // identified by |identifier|.
    bool getPublicKey(const std::string& identifier,
                      std::string* name,
                      KeyType* type,
                      std::string* key);
    void getPublicKeyHeader(PublicKeyHeader* header);

    size_t size() const { return keys_.size(); }
    std::pair<std::string, const Key*> operator[](const size_t idx) const;
    static uint32_t maxCertificateSize() { return kMaxX509CertSize; }

private:
    std::string getKeyStorePath();
    std::string getSysPrivKeyPath();
    std::string getSysPubKeyPath();

    bool generateSystemCertificate(KeyType type = KeyType::EllipticCurve);

    bool readSystemCertificate();
    bool writeSystemCertificate();
    bool readPublicKeys(adbwifi::proto::KeyStore& key_store);
    bool writePublicKeys();

    std::unordered_map<std::string, std::unique_ptr<Key>> keys_;
    bssl::UniquePtr<EVP_PKEY> evp_pkey_;
    bssl::UniquePtr<X509> x509_;
    std::unique_ptr<Key> private_key_;
    std::unique_ptr<Key> public_cert_;
    std::string keystore_path_;
    std::unique_ptr<DeviceIdentifier> device_id_;
    adbwifi::proto::KeyStore key_store_;
};

KeyStore::KeyStore(std::string_view keystore_path) :
    keystore_path_(keystore_path) {
    device_id_.reset(new DeviceIdentifier(keystore_path_));
}

bool KeyStore::init() {
    LOG(ERROR) << "Checking unique device id";
    if (!device_id_->init() || device_id_->getUniqueDeviceId().empty()) {
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
    return readPublicKeys(key_store_);
}

Key* KeyStore::getSystemPublicKey(KeyType type) {
    if (public_cert_ && public_cert_->type() == type) {
        return public_cert_.get();
    }
    return nullptr;
}

bool KeyStore::storePublicKey(const PublicKeyHeader* header,
                              const char* public_key) {
    KeyType key_type;
    if (!getKeyTypeFromValue(header->type, &key_type)) {
        LOG(ERROR) << "Unknown public key type. Unable to store the key.";
        return false;
    }
    std::unique_ptr<Key> keyPtr = createKey(key_type, header->name, public_key);
    if (!keyPtr) {
        LOG(ERROR) << "Unable to store public key";
        return false;
    }
    std::string identifier(header->id);
    keys_[identifier] = std::move(keyPtr);
    if (!writePublicKeys()) {
        LOG(ERROR) << "Unable to write public key store";
        keys_.erase(identifier);
        return false;
    }
    return true;

}

bool KeyStore::getPublicKey(const std::string& identifier,
                            std::string* name,
                            KeyType* type,
                            std::string* key) {
    auto it = keys_.find(identifier);
    if (it == keys_.end()) {
        return false;
    }
    *type = it->second->type();
    *name = it->second->name();
    *key = it->second->c_str();
    return true;
}

std::pair<std::string, const Key*> KeyStore::operator[](const size_t idx) const {
    auto it = keys_.begin();
    std::advance(it, idx);
    return std::pair<std::string, const Key*>(it->first, it->second.get());
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

bool KeyStore::generateSystemCertificate(KeyType /* type */) {
    LOG(ERROR) << "Generating system public key pair";
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
                               reinterpret_cast<const unsigned char*>("localhost"),
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
    return true;
}

template<typename F, typename... Args>
static std::string writePemToMem(F writeFunc, Args&&... args) {
    bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
    if (!bio) {
        return std::string();
    }
    if (!writeFunc(bio.get(), std::forward<Args>(args)...)) {
        return std::string();
    }
    char* mem = nullptr;
    long size = BIO_get_mem_data(bio.get(), &mem);
    if (size <= 0 || mem == nullptr) {
        return std::string();
    }
    return mem;
}

bool KeyStore::readSystemCertificate() {
    LOG(ERROR) << "Reading system certificate";
    std::unique_ptr<FILE, decltype(&fclose)> file(nullptr, &fclose);
    file.reset(fopen(getSysPrivKeyPath().c_str(), "rb"));
    if (!file) {
        LOG(ERROR) << "Unable to open system private key: " << strerror(errno);
        return false;
    }

    evp_pkey_.reset(PEM_read_PrivateKey(file.get(), nullptr, nullptr, nullptr));
    if (!evp_pkey_) {
        LOG(ERROR) << "Unable to read system private key: "
                   << sslErrorStr().c_str();
        return false;
    }

    file.reset(fopen(getSysPubKeyPath().c_str(), "rb"));
    if (!file) {
        LOG(ERROR) << "Unable to open system public key";
        return false;
    }
    x509_.reset(PEM_read_X509(file.get(), nullptr, nullptr, nullptr));
    if (!x509_) {
        LOG(ERROR) << "Unable to read public system key";
        return false;
    }
    std::string certStr = writePemToMem(PEM_write_bio_X509, x509_.get());
    if (certStr.empty()) {
        LOG(ERROR) << "Unable to write certificate to string";
        return false;
    }
    public_cert_.reset(new EllipticCurveKey("systemCert", certStr.c_str()));

    std::string privateKeyStr = writePemToMem(PEM_write_bio_PrivateKey,
                                              evp_pkey_.get(),
                                              nullptr, nullptr, 0,
                                              nullptr, nullptr);
    if (certStr.empty()) {
        LOG(ERROR) << "Unable to write private key to string";
        return false;
    }
    private_key_.reset(new EllipticCurveKey("systemPK", privateKeyStr.c_str()));

    return true;
}

bool KeyStore::writeSystemCertificate() {
    return true;
}

bool KeyStore::readPublicKeys(adbwifi::proto::KeyStore& key_store) {
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
        my_unlink(store_name.c_str());
        return false;
    }

    return true;
}

bool KeyStore::writePublicKeys() {
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
    SelfDestructingFile file(tempName.c_str(), std::ofstream::binary);
    if (!file) {
        LOG(ERROR) << "Failed to open keystore file '" << tempName
                   << "' for writing: " << strerror(errno);
        return false;
    }

    // Write out all the saved keys
    for (const auto& idKey : keys_) {
        const std::string& guid = idKey.first;
        const Key* key = idKey.second.get();
        auto* pkey = key_store.add_keys();
        pkey->set_guid(guid);
        pkey->set_name(key->name());
        pkey->set_type(static_cast<uint8_t>(key->type()));
        pkey->set_public_key(key->c_str());
    }

    if (!key_store.SerializeToOstream(file.get())) {
        LOG(ERROR) << "Unable to write key store out.";
        return false;
    }
    file.closeAndDisarm();

    // Replace the existing key store with the new one.
    std::string toBeDeleted = storeName;
    toBeDeleted += ".tbd";
    if (my_rename(storeName.c_str(), toBeDeleted.c_str()) != 0) {
        // Don't exit here, this is not necessarily an error, the first time
        // around there is no key store.
        LOG(WARNING) << "Failed to rename old key store";
    }

    if (my_rename(tempName.c_str(), storeName.c_str()) != 0) {
        LOG(ERROR) << "Failed to replace old key store";
        my_rename(toBeDeleted.c_str(), storeName.c_str());
        my_unlink(tempName.c_str());
        return false;
    }

    my_unlink(toBeDeleted.c_str());

    LOG(ERROR) << "Successfully wrote key store";
    key_store_.CopyFrom(key_store);

    return true;
}

void KeyStore::getPublicKeyHeader(PublicKeyHeader* header) {
    header->version = kCurrentKeyHeaderVersion;
    header->type = static_cast<uint8_t>(public_cert_->type());
    header->bits = public_cert_->bits();
    header->payload = public_cert_->size();

    auto device_name = device_id_->getDeviceName();
    auto max_name_size = sizeof(header->name);
    memset(header->name, 0, max_name_size);
    strncpy(header->name, device_name.data(),
            device_name.size() < max_name_size ?
                device_name.size() : max_name_size - 1);

    auto device_id = device_id_->getUniqueDeviceId();
    auto max_id_size = sizeof(header->id);
    memset(header->id, 0, max_id_size);
    strncpy(header->id, device_id.data(),
            device_id.size() < max_id_size ?
                device_id.size() : max_id_size - 1);
}

std::string KeyStore::getKeyStorePath() {
    return keystore_path_ + OS_PATH_SEPARATOR + kKeyStoreName;
}

std::string KeyStore::getSysPrivKeyPath() {
    return keystore_path_ + OS_PATH_SEPARATOR + kPrivateKeyName;
}

std::string KeyStore::getSysPubKeyPath() {
    return keystore_path_ + OS_PATH_SEPARATOR + kPublicKeyName;
}

std::unique_ptr<KeyStore> sKeyStore;

#if defined(__ANDROID__)
using namespace std::chrono_literals;

constexpr int kInitRetries = 60;
void retryKeyStoreInitLoop(std::function<void(bool)> callback) {
    // Let's give up after some time.
    for (int i = 0; i < kInitRetries; ++i) {
        LOG(INFO) << "keystore init retry loop sleeping";
        std::this_thread::sleep_for(1s);
        if (sKeyStore->init()) {
            LOG(INFO) << "keystore init retry loop succeeded";
            callback(true);
            return;
        }
    }
    LOG(WARNING) << "keystore init failed.";
    callback(false);
}
#endif // __ANDROID__
}  // namespace

KeyStoreCtx keystore_init(const char* keystore_path,
                          void* opaque,
                          void (*cb)(KeyStoreCtx, void*)) {
    if (sKeyStore == nullptr) {
        sKeyStore.reset(new KeyStore(keystore_path));
    }
    if (!sKeyStore->init()) {
#if defined(__ANDROID__)
        // We failed to initialize. This can happen on the device if
        // the data partition is not mounted yet. Try again later.
        LOG(ERROR) << "key store init failed, launching retry thread";
        std::thread(std::bind(&retryKeyStoreInitLoop,
                [cb, opaque](bool result) {
                    if (cb == nullptr) return;
                    if (result) {
                        cb(static_cast<KeyStoreCtx>(sKeyStore.get()), opaque);
                        return;
                    }
                    cb(nullptr, opaque);
                })).detach();
#endif // __ANDROID__
        return nullptr;
    }

    return static_cast<KeyStoreCtx>(sKeyStore.get());
}

void keystore_public_key_header(KeyStoreCtx ctx,
                                PublicKeyHeader* header) {
    CHECK(ctx);

    auto* p = reinterpret_cast<KeyStore*>(ctx);
    p->getPublicKeyHeader(header);
}

uint32_t keystore_system_public_key(KeyStoreCtx ctx,
                                    char* out_public_key) {
    CHECK(ctx);

    auto* p = reinterpret_cast<KeyStore*>(ctx);
    auto* key = p->getSystemPublicKey();
    if (key == nullptr) {
        return 0;
    }
    strncpy(out_public_key, key->c_str(), key->size());
    return key->size();
}

bool keystore_store_public_key(KeyStoreCtx ctx,
                               const PublicKeyHeader* header,
                               const char* public_key) {
    CHECK(ctx);

    auto* p = reinterpret_cast<KeyStore*>(ctx);
    return p->storePublicKey(header, public_key);
}

uint32_t keystore_max_certificate_size(KeyStoreCtx /* ctx */) {
    return KeyStore::maxCertificateSize();
}

KeyStoreCtx keystore_get(void) {
    return static_cast<KeyStoreCtx>(sKeyStore.get());
}
