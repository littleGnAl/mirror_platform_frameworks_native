#include <android/binder_libbinder.h>
#include <android/persistable_bundle.h>
#include <binder/PersistableBundle.h>
#include <string.h>

#include <set>

__BEGIN_DECLS

struct APersistableBundle {
    APersistableBundle(const APersistableBundle& pBundle) : mPBundle(pBundle.mPBundle) {}
    APersistableBundle() = default;
    android::os::PersistableBundle mPBundle;
};

APersistableBundle* _Nullable APersistableBundle_new() {
    return new (std::nothrow) APersistableBundle();
}

APersistableBundle* _Nullable APersistableBundle_dup(const APersistableBundle* pBundle) {
    if (pBundle) {
        return new APersistableBundle(*pBundle);
    } else {
        return new APersistableBundle();
    }
}

void APersistableBundle_delete(APersistableBundle* pBundle) {
    if (pBundle) {
        free(pBundle);
    }
}

bool APersistableBundle_isEqual(const APersistableBundle* lhs, const APersistableBundle* rhs) {
    if (lhs && rhs) {
        return lhs->mPBundle == rhs->mPBundle;
    } else {
        return false;
    }
}

binder_status_t APersistableBundle_readFromParcel(const AParcel* parcel,
                                                  APersistableBundle* _Nullable* outPBundle) {
    if (!parcel || !outPBundle) return STATUS_BAD_VALUE;
    APersistableBundle* newPBundle = APersistableBundle_new();
    if (newPBundle == nullptr) return STATUS_NO_MEMORY;
    binder_status_t status =
            newPBundle->mPBundle.readFromParcel(AParcel_viewPlatformParcel(parcel));
    if (status == STATUS_OK) {
        *outPBundle = newPBundle;
    }
    return status;
}

binder_status_t APersistableBundle_writeToParcel(const APersistableBundle* pBundle,
                                                 AParcel* parcel) {
    if (!parcel || !pBundle) return STATUS_BAD_VALUE;
    return pBundle->mPBundle.writeToParcel(AParcel_viewPlatformParcel(parcel));
}

size_t APersistableBundle_size(APersistableBundle* pBundle) {
    return pBundle->mPBundle.size();
}
size_t APersistableBundle_erase(APersistableBundle* pBundle, const char* key) {
    return pBundle->mPBundle.erase(android::String16(key));
}
void APersistableBundle_putBoolean(APersistableBundle* pBundle, const char* key, bool val) {
    pBundle->mPBundle.putBoolean(android::String16(key), val);
}
void APersistableBundle_putInt(APersistableBundle* pBundle, const char* key, int32_t val) {
    pBundle->mPBundle.putInt(android::String16(key), val);
}
void APersistableBundle_putLong(APersistableBundle* pBundle, const char* key, int64_t val) {
    pBundle->mPBundle.putLong(android::String16(key), val);
}
void APersistableBundle_putDouble(APersistableBundle* pBundle, const char* key, double val) {
    pBundle->mPBundle.putDouble(android::String16(key), val);
}
void APersistableBundle_putString(APersistableBundle* pBundle, const char* key, const char* val) {
    pBundle->mPBundle.putString(android::String16(key), android::String16(val));
}
void APersistableBundle_putBooleanVector(APersistableBundle* pBundle) {
    (void)pBundle;
}
void APersistableBundle_putIntVector(APersistableBundle* pBundle) {
    (void)pBundle;
}
void APersistableBundle_putLongVector(APersistableBundle* pBundle) {
    (void)pBundle;
}
void APersistableBundle_putDoubleVector(APersistableBundle* pBundle) {
    (void)pBundle;
}
void APersistableBundle_putStringVector(APersistableBundle* pBundle) {
    (void)pBundle;
}
void APersistableBundle_putPersistableBundle(APersistableBundle* pBundle) {
    (void)pBundle;
}
bool APersistableBundle_getBoolean(const APersistableBundle* pBundle, const char* key, bool* val) {
    return pBundle->mPBundle.getBoolean(android::String16(key), val);
}
bool APersistableBundle_getInt(const APersistableBundle* pBundle, const char* key, int32_t* val) {
    return pBundle->mPBundle.getInt(android::String16(key), val);
}
bool APersistableBundle_getLong(const APersistableBundle* pBundle, const char* key, int64_t* val) {
    return pBundle->mPBundle.getLong(android::String16(key), val);
}
bool APersistableBundle_getDouble(const APersistableBundle* pBundle, const char* key, double* val) {
    return pBundle->mPBundle.getDouble(android::String16(key), val);
}
bool APersistableBundle_getString(const APersistableBundle* pBundle, const char* key, char** val) {
    android::String16 outVal;
    bool ret = pBundle->mPBundle.getString(android::String16(key), &outVal);
    if (ret) {
        *val = strdup(android::String8(outVal).c_str());
    }
    return ret;
}
void APersistableBundle_getBooleanVector(const APersistableBundle* pBundle) {
    (void)pBundle;
}
void APersistableBundle_getIntVector(const APersistableBundle* pBundle) {
    (void)pBundle;
}
void APersistableBundle_getLongVector(const APersistableBundle* pBundle) {
    (void)pBundle;
}
void APersistableBundle_getDoubleVector(const APersistableBundle* pBundle) {
    (void)pBundle;
}
void APersistableBundle_getStringVector(const APersistableBundle* pBundle) {
    (void)pBundle;
}
void APersistableBundle_getPersistableBundle(const APersistableBundle* pBundle) {
    (void)pBundle;
}
size_t getKeys(const std::set<android::String16>& keySet, char*** outKeys) {
    size_t num = keySet.size();
    if (num > 0) {
        char** keys = (char**)malloc(num * sizeof(char*));
        if (keys) {
            int i = 0;
            for (const android::String16& key : keySet) {
                keys[i] = strdup(android::String8(key).c_str());
                i++;
            }
            *outKeys = keys;
            return num;
        }
    }
    return 0;
}

size_t APersistableBundle_getBooleanKeys(const APersistableBundle* pBundle, char*** outKeys) {
    std::set<android::String16> ret = pBundle->mPBundle.getBooleanKeys();
    return getKeys(ret, outKeys);
}
size_t APersistableBundle_getIntKeys(const APersistableBundle* pBundle, char*** outKeys) {
    std::set<android::String16> ret = pBundle->mPBundle.getIntKeys();
    return getKeys(ret, outKeys);
}
size_t APersistableBundle_getLongKeys(const APersistableBundle* pBundle, char*** outKeys) {
    std::set<android::String16> ret = pBundle->mPBundle.getLongKeys();
    return getKeys(ret, outKeys);
}
size_t APersistableBundle_getDoubleKeys(const APersistableBundle* pBundle, char*** outKeys) {
    std::set<android::String16> ret = pBundle->mPBundle.getDoubleKeys();
    return getKeys(ret, outKeys);
}
size_t APersistableBundle_getStringKeys(const APersistableBundle* pBundle, char*** outKeys) {
    std::set<android::String16> ret = pBundle->mPBundle.getStringKeys();
    return getKeys(ret, outKeys);
}

void APersistableBundle_getBooleanVectorKeys(const APersistableBundle* pBundle) {
    (void)pBundle;
}
void APersistableBundle_getIntVectorKeys(const APersistableBundle* pBundle) {
    (void)pBundle;
}
void APersistableBundle_getLongVectorKeys(const APersistableBundle* pBundle) {
    (void)pBundle;
}
void APersistableBundle_getDoubleVectorKeys(const APersistableBundle* pBundle) {
    (void)pBundle;
}
void APersistableBundle_getStringVectorKeys(const APersistableBundle* pBundle) {
    (void)pBundle;
}
void APersistableBundle_getPersistableBundleKeys(const APersistableBundle* pBundle) {
    (void)pBundle;
}

__END_DECLS
