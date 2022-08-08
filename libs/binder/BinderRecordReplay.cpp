#include <binder/BinderRecordReplay.h>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <binder/Parcel.h>

namespace android {

namespace BinderRecordReplay {

status_t recordTransaction(int fd, uint32_t code, const Parcel& data, uint32_t flags,
                           status_t err) {
    transactionHeader
            header{.code = code,
                   .flags = flags,
                   .dataSize = (uint64_t)data.dataSize(),
                   .statusReturned = (int32_t)err,
                   .version = data.isForRpc() ? (uint32_t)1 : (uint32_t)0,
                   // FIXME: need to get version from data->rpcfields->rpcsession->version,
                   // but this not public information
                   .isForRpc = data.isForRpc() ? isRpc::NOT_RPC : isRpc::YES_RPC};

    if (!android::base::WriteFully(fd, &header, sizeof(header))) {
        LOG(INFO) << "Failed to write transactionHeader to fd " << fd;
        return DEAD_OBJECT;
    }

    if (!android::base::WriteFully(fd, data.data(), header.dataSize)) {
        LOG(INFO) << "Failed to write transaction data to fd " << fd;
        return DEAD_OBJECT;
    }

    uint8_t zeros[8] = {0};
    if (!android::base::WriteFully(fd, zeros, ((8 - header.dataSize % 8) % 8))) {
        LOG(INFO) << "Failed to write recording padding to fd " << fd;
        return DEAD_OBJECT;
    }

    return NO_ERROR;
}

} // namespace BinderRecordReplay

} // namespace android
