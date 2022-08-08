#include <binder/BinderRecordReplay.h>

#include <android-base/file.h>
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
                   .errReturned = (uint32_t)err,
                   .version = data.isForRpc() ? (uint32_t)1 : (uint32_t)0,
                   // FIXME: need to get version from data->rpcfields->rpcsession->version,
                   // but this may not be public information
                   .isForRpc = data.isForRpc() ? isRpc::NOT_RPC : isRpc::YES_RPC};

    if (status_t err = android::base::WriteFully(fd, &header, sizeof(header)); err != NO_ERROR) {
        return err;
    }

    if (status_t err = android::base::WriteFully(fd, data.data(), header.dataSize);
        err != NO_ERROR) {
        return err;
    }

    // TODO: More succint way to do this (aligning to 8 bytes)?
    // Moreover is it even neccesary?
    uint8_t zeros[8] = {0};
    if (status_t err = android::base::WriteFully(fd, zeros, header.dataSize % 8); err != NO_ERROR) {
        return err;
    }

    return NO_ERROR;
}

} // namespace BinderRecordReplay

} // namespace android
