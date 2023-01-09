/*
 * Copyright (C) 2022, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/unique_fd.h>
#include <binder/BinderRecordReplay.h>
#include <sys/mman.h>
#include <algorithm>

using android::Parcel;
using android::base::borrowed_fd;
using android::base::unique_fd;
using android::binder::debug::RecordedTransaction;

#define PADDING8(s) ((8 - (s) % 8) % 8)

static_assert(PADDING8(0) == 0);
static_assert(PADDING8(1) == 7);
static_assert(PADDING8(7) == 1);
static_assert(PADDING8(8) == 0);

// Transactions are sequentially recorded to a file descriptor.
//
// An individual RecordedTransaction is written with the following format:
//
// WARNING: Though the following format is designed to be stable and
// extensible, it is under active development and should be considered
// unstable until this warning is removed.
//
// A RecordedTransaction is written to a file as a sequence of Chunks.
//
// A Chunk consists of a ChunkDescriptor, Data, Padding, and a Checksum.
//
// Data and Padding may each be zero-length as specified by the
// ChunkDescriptor.
//
// The ChunkDescriptor identifies the type of data in the chunk in the 29 most
// significant bits of the chunk. The lower 3 bits before the chunk type declare
// the number of zero-bytes padding after the Data section to land on an 8-byte
// boundary by the end of the Chunk.
//
// The checksum is a 64-bit wide XOR of all previous data from the start of the
// ChunkDescriptor to the end of Padding.
//
// ┌───────────────────────────────────────┐
// │Chunk                                  │
// │┌─────────────────────────────────────┐│
// ││ChunkDescriptor                      ││
// ││┌───────────────────────────────────┐││
// │││31                                0│││
// ││││chunkType             paddingSize││││
// │││└─────────────29──────────────┴─3─┘│││
// │││uint32_t                        └──┼┼┼───┐
// ││├───────────────────────────────────┤││   │
// │││dataSize                           ├┼┼─┐ │
// │││uint32_t                           │││ │ │
// ││└───────────────────────────────────┘││ │ │
// │└─────────────────────────────────────┘│ │ │
// │┌─────────────────────────────────────┐│ │ │
// ││Data                                 ││ │ │
// ││bytes * dataSize                     │◀─┘ │
// ││                                     ││   │
// │└─────────────────────────────────────┘│   │
// │┌─────────────────────────────────────┐│   │
// ││Padding                              ││   │
// ││bytes * paddingSize                  │◀───┘
// │└─────────────────────────────────────┘│
// │┌─────────────────────────────────────┐│
// ││checksum                             ││
// ││uint64_t                             ││
// │└─────────────────────────────────────┘│
// └───────────────────────────────────────┘
//
// A RecordedTransaction is written as a Header Chunk with fields about the
// transaction, a Data Parcel chunk, a Reply Parcel Chunk, and an End Chunk.
// ┌──────────────────────┐
// │     Header Chunk     │
// ├──────────────────────┤
// │  Sent Parcel Chunk   │
// ├──────────────────────┤
// │  Reply Parcel Chunk  │
// ├──────────────────────┤
// ║      End Chunk       ║
// ╚══════════════════════╝
//
// On reading a RecordedTransaction, an unrecognized chunk is checksummed
// then skipped according to size information in the ChunkDescriptor. Chunks
// are read and either assimilated or skipped until an End Chunk is
// encountered. This has three notable implications:
//
// 1. Older and newer implementations should be able to read one another's
//    Transactions, though there will be loss of information.
// 2. With the exception of the End Chunk, Chunks can appear in any order
//    and even repeat, though this is not recommended.
// 3. If any Chunk is repeated, old values will be overwritten by versions
//    encountered later in the file.
//
// No effort is made to ensure the expected chunks are present. A single
// End Chunk may therefore produce an empty, meaningless RecordedTransaction.

RecordedTransaction::RecordedTransaction(RecordedTransaction &&t) noexcept {
    mHeader = t.mHeader;
    mSent.setData(t.getDataParcel().data(), t.getDataParcel().dataSize());
    mReply.setData(t.getReplyParcel().data(), t.getReplyParcel().dataSize());
}

std::optional<RecordedTransaction> RecordedTransaction::fromDetails(uint32_t code, uint32_t flags,
                                                                    timespec timestamp,
                                                                    const Parcel &dataParcel,
                                                                    const Parcel &replyParcel,
                                                                    status_t err) {
    RecordedTransaction t;
    t.mHeader = {code,
                 flags,
                 static_cast<int32_t>(err),
                 dataParcel.isForRpc() ? static_cast<uint32_t>(1) : static_cast<uint32_t>(0),
                 static_cast<int64_t>(timestamp.tv_sec),
                 static_cast<int32_t>(timestamp.tv_nsec),
                 0};

    if (t.mSent.setData(dataParcel.data(), dataParcel.dataSize()) != android::NO_ERROR) {
        LOG(INFO) << "Failed to set sent parcel data.";
        return std::nullopt;
    }

    if (t.mReply.setData(replyParcel.data(), replyParcel.dataSize()) != android::NO_ERROR) {
        LOG(INFO) << "Failed to set reply parcel data.";
        return std::nullopt;
    }

    return std::optional<RecordedTransaction>(std::move(t));
}

enum {
    HEADER_CHUNK = 1 << 3,
    DATA_PARCEL_CHUNK = 1 << 4,
    REPLY_PARCEL_CHUNK = 1 << 5,
    INVALID_CHUNK = 0x00fffff0,
    END_CHUNK = 0x00fffff8,
};

struct ChunkDescriptor {
    uint32_t chunkType = 0;
    uint32_t dataSize = 0;
    uint8_t paddingSize = 0;
};

typedef uint64_t transaction_checksum_t;

static android::status_t readChunkDescriptor(borrowed_fd fd, ChunkDescriptor *chunkOut,
                                             transaction_checksum_t *sum) {
    uint32_t packedDescriptor[2] = {0, 0};
    if (!android::base::ReadFully(fd, packedDescriptor, sizeof(uint32_t) * 2)) {
        LOG(INFO) << "Failed to read Chunk Descriptor from fd " << fd.get();
        return android::UNKNOWN_ERROR;
    }
    chunkOut->chunkType = packedDescriptor[0] & 0xfffffff8;
    chunkOut->paddingSize = static_cast<uint8_t>(packedDescriptor[0] & 0x00000007);
    chunkOut->dataSize = packedDescriptor[1];

    if (PADDING8(chunkOut->dataSize) != chunkOut->paddingSize) {
        chunkOut->chunkType = INVALID_CHUNK;
        LOG(INFO) << "Chunk data and padding sizes do not align." << fd.get();
        return android::BAD_VALUE;
    }
    *sum ^= *reinterpret_cast<transaction_checksum_t *>(packedDescriptor);
    return android::NO_ERROR;
}

std::optional<RecordedTransaction> RecordedTransaction::fromFile(const unique_fd &fd) {
    RecordedTransaction t;
    ChunkDescriptor chunk;
    const long pageSize = sysconf(_SC_PAGE_SIZE);
    do {
        transaction_checksum_t checksum = 0;
        if (NO_ERROR != readChunkDescriptor(fd, &chunk, &checksum)) {
            LOG(INFO) << "Failed to read chunk descriptor.";
            return std::nullopt;
        }
        off_t fdCurrentPosition = lseek(fd.get(), 0, SEEK_CUR);
        off_t mmapPageAlignedStart = (fdCurrentPosition / pageSize) * pageSize;
        off_t mmapPayloadStartOffset = fdCurrentPosition - mmapPageAlignedStart;

        std::vector<std::byte> buffer;

        size_t chunkPayloadSize =
                chunk.dataSize + chunk.paddingSize + sizeof(transaction_checksum_t);
        if (PADDING8(chunkPayloadSize) != 0) {
            LOG(INFO) << "Invalid chunk size, not aligned " << chunkPayloadSize;
            return std::nullopt;
        }

        transaction_checksum_t *payloadMap = reinterpret_cast<transaction_checksum_t *>(
                mmap(NULL, chunkPayloadSize + mmapPayloadStartOffset, PROT_READ, MAP_SHARED,
                     fd.get(), mmapPageAlignedStart));
        payloadMap += mmapPayloadStartOffset /
                sizeof(transaction_checksum_t); // Skip chunk descriptor and required mmap
                                                // page-alignment
        if (payloadMap == MAP_FAILED) {
            LOG(INFO) << "Memory mapping failed for fd " << fd.get() << ": " << errno << " "
                      << strerror(errno);
            return std::nullopt;
        }
        for (size_t checksumIndex = 0;
             checksumIndex < chunkPayloadSize / sizeof(transaction_checksum_t); checksumIndex++) {
            checksum ^= payloadMap[checksumIndex];
        }
        if (checksum != 0) {
            LOG(INFO) << "Checksum failed.";
            return std::nullopt;
        }
        lseek(fd.get(), chunkPayloadSize, SEEK_CUR);

        switch (chunk.chunkType) {
            case HEADER_CHUNK: {
                if (chunk.dataSize != static_cast<uint32_t>(sizeof(TransactionHeader))) {
                    LOG(INFO) << "Header Chunk indicated size " << chunk.dataSize << "; Expected "
                              << sizeof(TransactionHeader) << ".";
                    return std::nullopt;
                }
                t.mHeader = *reinterpret_cast<TransactionHeader *>(payloadMap);
                break;
            }
            case DATA_PARCEL_CHUNK: {
                if (t.mSent.setData(reinterpret_cast<const unsigned char *>(payloadMap),
                                    chunk.dataSize) != android::NO_ERROR) {
                    LOG(INFO) << "Failed to set sent parcel data.";
                    return std::nullopt;
                }
                break;
            }
            case REPLY_PARCEL_CHUNK: {
                if (t.mReply.setData(reinterpret_cast<const unsigned char *>(payloadMap),
                                     chunk.dataSize) != android::NO_ERROR) {
                    LOG(INFO) << "Failed to set reply parcel data.";
                    return std::nullopt;
                }
                break;
            }
            case INVALID_CHUNK:
                LOG(INFO) << "Invalid chunk.";
                return std::nullopt;
            case END_CHUNK:
                FALLTHROUGH_INTENDED;
            default:
                LOG(INFO) << "Unrecognized chunk.";
                continue;
        }
    } while (chunk.chunkType != END_CHUNK);

    return std::optional<RecordedTransaction>(std::move(t));
}

android::status_t RecordedTransaction::writeChunk(borrowed_fd fd, uint32_t chunkType,
                                                  size_t byteCount, const uint8_t *data) const {
    if (chunkType & 0x7) {
        LOG(INFO) << "Invalid Chunk type. Lower 3 bits must be 0";
        return BAD_VALUE;
    }
    // Pack Chunk Descriptor
    const uint32_t descriptorField1 = chunkType | static_cast<uint32_t>(PADDING8(byteCount));
    const uint32_t dataByteCount = static_cast<uint32_t>(byteCount);

    // Prepare Chunk content as byte *
    const std::byte *descriptorBytes = reinterpret_cast<const std::byte *>(&descriptorField1);
    const std::byte *dataByteCountBytes = reinterpret_cast<const std::byte *>(&dataByteCount);
    const std::byte *dataBytes = reinterpret_cast<const std::byte *>(data);

    // Add Chunk to intermediate buffer, except checksum
    std::vector<std::byte> buffer;
    buffer.insert(buffer.end(), descriptorBytes, descriptorBytes + sizeof(uint32_t));
    buffer.insert(buffer.end(), dataByteCountBytes, dataByteCountBytes + sizeof(uint32_t));
    buffer.insert(buffer.end(), dataBytes, dataBytes + byteCount);
    std::byte zero{0};
    buffer.insert(buffer.end(), PADDING8(byteCount), zero);

    // Calculate checksum from buffer
    transaction_checksum_t *checksumData =
            reinterpret_cast<transaction_checksum_t *>(buffer.data());
    transaction_checksum_t checksumValue = 0;
    for (size_t idx = 0; idx < (buffer.size() / sizeof(transaction_checksum_t)); idx++) {
        checksumValue ^= checksumData[idx];
    }

    // Write checksum to buffer
    std::byte *checksumBytes = reinterpret_cast<std::byte *>(&checksumValue);
    buffer.insert(buffer.end(), checksumBytes, checksumBytes + sizeof(transaction_checksum_t));

    // Write buffer to file
    if (!android::base::WriteFully(fd, buffer.data(), buffer.size())) {
        LOG(INFO) << "Failed to write chunk fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    return NO_ERROR;
}

android::status_t RecordedTransaction::dumpToFile(const unique_fd &fd) const {
    if (NO_ERROR !=
        writeChunk(fd, HEADER_CHUNK, sizeof(TransactionHeader),
                   reinterpret_cast<const uint8_t *>(&mHeader))) {
        LOG(INFO) << "Failed to write transactionHeader to fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    if (NO_ERROR != writeChunk(fd, DATA_PARCEL_CHUNK, mSent.dataSize(), mSent.data())) {
        LOG(INFO) << "Failed to write sent Parcel to fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    if (NO_ERROR != writeChunk(fd, REPLY_PARCEL_CHUNK, mReply.dataSize(), mReply.data())) {
        LOG(INFO) << "Failed to write reply Parcel to fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    if (NO_ERROR != writeChunk(fd, END_CHUNK, 0, NULL)) {
        LOG(INFO) << "Failed to write end chunk to fd " << fd.get();
        return UNKNOWN_ERROR;
    }
    return NO_ERROR;
}

uint32_t RecordedTransaction::getCode() const {
    return mHeader.code;
}

uint32_t RecordedTransaction::getFlags() const {
    return mHeader.flags;
}

int32_t RecordedTransaction::getReturnedStatus() const {
    return mHeader.statusReturned;
}

timespec RecordedTransaction::getTimestamp() const {
    time_t sec = mHeader.timestampSeconds;
    int32_t nsec = mHeader.timestampNanoseconds;
    return (timespec){.tv_sec = sec, .tv_nsec = nsec};
}

uint32_t RecordedTransaction::getVersion() const {
    return mHeader.version;
}

const Parcel &RecordedTransaction::getDataParcel() const {
    return mSent;
}

const Parcel &RecordedTransaction::getReplyParcel() const {
    return mReply;
}
