#pragma once

#include <android-base/file.h>
#include <android-base/unique_fd.h>
#include <binder/Parcel.h>

namespace android {

namespace BinderRecordReplay {

enum class isRpc : uint8_t { NOT_RPC = 0, YES_RPC = 1 };

struct transactionHeader {
    uint32_t code = 0;
    uint32_t flags = 0;
    uint64_t dataSize = 0;
    int32_t statusReturned = 0;
    uint32_t version = 0;
    isRpc isForRpc = isRpc::NOT_RPC;
    uint8_t reserved[7];
};
static_assert(sizeof(transactionHeader) == 32);

// Transactions are sequentially recorded to the file descriptor in the following format:
//
// transactionHeader  (32 bytes)
// Parcel data        (transactionHeader.dataSize bytes)
// padding            (enough bytes to align the next header to 8 bytes)
// [repeats with next transaction]
status_t recordTransaction(int fd, uint32_t code, const Parcel& data, uint32_t flags, status_t err);

} // namespace BinderRecordReplay

} // namespace android
