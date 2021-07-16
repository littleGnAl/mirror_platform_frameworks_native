/*
 * Copyright (C) 2018 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
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

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wconversion"

#undef LOG_TAG
#define LOG_TAG "DisplayIdentification"

#include <algorithm>
#include <cctype>
#include <numeric>
#include <optional>

#include <log/log.h>

#include "DisplayIdentification.h"

namespace android {
namespace {

using byte_view = std::basic_string_view<uint8_t>;

constexpr size_t kEdidBlockSize = 128;
constexpr size_t kEdidHeaderLength = 5;

constexpr uint16_t kFallbackEdidManufacturerId = 0;
constexpr uint16_t kVirtualEdidManufacturerId = 0xffffu;

static constexpr const uint32_t kCrcTable[] = {
        0x00000000, 0x04C11DB7, 0x09823B6E, 0x0D4326D9, 0x130476DC, 0x17C56B6B, 0x1A864DB2,
        0x1E475005, 0x2608EDB8, 0x22C9F00F, 0x2F8AD6D6, 0x2B4BCB61, 0x350C9B64, 0x31CD86D3,
        0x3C8EA00A, 0x384FBDBD, 0x4C11DB70, 0x48D0C6C7, 0x4593E01E, 0x4152FDA9, 0x5F15ADAC,
        0x5BD4B01B, 0x569796C2, 0x52568B75, 0x6A1936C8, 0x6ED82B7F, 0x639B0DA6, 0x675A1011,
        0x791D4014, 0x7DDC5DA3, 0x709F7B7A, 0x745E66CD, 0x9823B6E0, 0x9CE2AB57, 0x91A18D8E,
        0x95609039, 0x8B27C03C, 0x8FE6DD8B, 0x82A5FB52, 0x8664E6E5, 0xBE2B5B58, 0xBAEA46EF,
        0xB7A96036, 0xB3687D81, 0xAD2F2D84, 0xA9EE3033, 0xA4AD16EA, 0xA06C0B5D, 0xD4326D90,
        0xD0F37027, 0xDDB056FE, 0xD9714B49, 0xC7361B4C, 0xC3F706FB, 0xCEB42022, 0xCA753D95,
        0xF23A8028, 0xF6FB9D9F, 0xFBB8BB46, 0xFF79A6F1, 0xE13EF6F4, 0xE5FFEB43, 0xE8BCCD9A,
        0xEC7DD02D, 0x34867077, 0x30476DC0, 0x3D044B19, 0x39C556AE, 0x278206AB, 0x23431B1C,
        0x2E003DC5, 0x2AC12072, 0x128E9DCF, 0x164F8078, 0x1B0CA6A1, 0x1FCDBB16, 0x018AEB13,
        0x054BF6A4, 0x0808D07D, 0x0CC9CDCA, 0x7897AB07, 0x7C56B6B0, 0x71159069, 0x75D48DDE,
        0x6B93DDDB, 0x6F52C06C, 0x6211E6B5, 0x66D0FB02, 0x5E9F46BF, 0x5A5E5B08, 0x571D7DD1,
        0x53DC6066, 0x4D9B3063, 0x495A2DD4, 0x44190B0D, 0x40D816BA, 0xACA5C697, 0xA864DB20,
        0xA527FDF9, 0xA1E6E04E, 0xBFA1B04B, 0xBB60ADFC, 0xB6238B25, 0xB2E29692, 0x8AAD2B2F,
        0x8E6C3698, 0x832F1041, 0x87EE0DF6, 0x99A95DF3, 0x9D684044, 0x902B669D, 0x94EA7B2A,
        0xE0B41DE7, 0xE4750050, 0xE9362689, 0xEDF73B3E, 0xF3B06B3B, 0xF771768C, 0xFA325055,
        0xFEF34DE2, 0xC6BCF05F, 0xC27DEDE8, 0xCF3ECB31, 0xCBFFD686, 0xD5B88683, 0xD1799B34,
        0xDC3ABDED, 0xD8FBA05A, 0x690CE0EE, 0x6DCDFD59, 0x608EDB80, 0x644FC637, 0x7A089632,
        0x7EC98B85, 0x738AAD5C, 0x774BB0EB, 0x4F040D56, 0x4BC510E1, 0x46863638, 0x42472B8F,
        0x5C007B8A, 0x58C1663D, 0x558240E4, 0x51435D53, 0x251D3B9E, 0x21DC2629, 0x2C9F00F0,
        0x285E1D47, 0x36194D42, 0x32D850F5, 0x3F9B762C, 0x3B5A6B9B, 0x0315D626, 0x07D4CB91,
        0x0A97ED48, 0x0E56F0FF, 0x1011A0FA, 0x14D0BD4D, 0x19939B94, 0x1D528623, 0xF12F560E,
        0xF5EE4BB9, 0xF8AD6D60, 0xFC6C70D7, 0xE22B20D2, 0xE6EA3D65, 0xEBA91BBC, 0xEF68060B,
        0xD727BBB6, 0xD3E6A601, 0xDEA580D8, 0xDA649D6F, 0xC423CD6A, 0xC0E2D0DD, 0xCDA1F604,
        0xC960EBB3, 0xBD3E8D7E, 0xB9FF90C9, 0xB4BCB610, 0xB07DABA7, 0xAE3AFBA2, 0xAAFBE615,
        0xA7B8C0CC, 0xA379DD7B, 0x9B3660C6, 0x9FF77D71, 0x92B45BA8, 0x9675461F, 0x8832161A,
        0x8CF30BAD, 0x81B02D74, 0x857130C3, 0x5D8A9099, 0x594B8D2E, 0x5408ABF7, 0x50C9B640,
        0x4E8EE645, 0x4A4FFBF2, 0x470CDD2B, 0x43CDC09C, 0x7B827D21, 0x7F436096, 0x7200464F,
        0x76C15BF8, 0x68860BFD, 0x6C47164A, 0x61043093, 0x65C52D24, 0x119B4BE9, 0x155A565E,
        0x18197087, 0x1CD86D30, 0x029F3D35, 0x065E2082, 0x0B1D065B, 0x0FDC1BEC, 0x3793A651,
        0x3352BBE6, 0x3E119D3F, 0x3AD08088, 0x2497D08D, 0x2056CD3A, 0x2D15EBE3, 0x29D4F654,
        0xC5A92679, 0xC1683BCE, 0xCC2B1D17, 0xC8EA00A0, 0xD6AD50A5, 0xD26C4D12, 0xDF2F6BCB,
        0xDBEE767C, 0xE3A1CBC1, 0xE760D676, 0xEA23F0AF, 0xEEE2ED18, 0xF0A5BD1D, 0xF464A0AA,
        0xF9278673, 0xFDE69BC4, 0x89B8FD09, 0x8D79E0BE, 0x803AC667, 0x84FBDBD0, 0x9ABC8BD5,
        0x9E7D9662, 0x933EB0BB, 0x97FFAD0C, 0xAFB010B1, 0xAB710D06, 0xA6322BDF, 0xA2F33668,
        0xBCB4666D, 0xB8757BDA, 0xB5365D03, 0xB1F740B4,
};

uint32_t crc32(const uint8_t* data, size_t length) {
    uint32_t crc = 0xFFFFFFFF;
    for (size_t i = 0; i < length; i++) {
        crc = (crc << 8) ^ kCrcTable[((crc >> 24) ^ data[i]) & 0xFF];
    }
    return crc;
}

uint32_t crc32(std::string_view sv) {
    return crc32(reinterpret_cast<const uint8_t*>(sv.data()), sv.size());
}

std::optional<uint8_t> getEdidDescriptorType(const byte_view& view) {
    if (view.size() < kEdidHeaderLength || view[0] || view[1] || view[2] || view[4]) {
        return {};
    }

    return view[3];
}

std::string_view parseEdidText(const byte_view& view) {
    std::string_view text(reinterpret_cast<const char*>(view.data()), view.size());
    text = text.substr(0, text.find('\n'));

    if (!std::all_of(text.begin(), text.end(), ::isprint)) {
        ALOGW("Invalid EDID: ASCII text is not printable.");
        return {};
    }

    return text;
}

// Big-endian 16-bit value encodes three 5-bit letters where A is 0b00001.
template <size_t I>
char getPnpLetter(uint16_t id) {
    static_assert(I < 3);
    const char letter = 'A' + (static_cast<uint8_t>(id >> ((2 - I) * 5)) & 0b00011111) - 1;
    return letter < 'A' || letter > 'Z' ? '\0' : letter;
}

DeviceProductInfo buildDeviceProductInfo(const Edid& edid) {
    DeviceProductInfo info;
    std::copy(edid.displayName.begin(), edid.displayName.end(), info.name.begin());
    info.name[edid.displayName.size()] = '\0';

    const auto productId = std::to_string(edid.productId);
    std::copy(productId.begin(), productId.end(), info.productId.begin());
    info.productId[productId.size()] = '\0';
    info.manufacturerPnpId = edid.pnpId;

    constexpr uint8_t kModelYearFlag = 0xff;
    constexpr uint32_t kYearOffset = 1990;

    const auto year = edid.manufactureOrModelYear + kYearOffset;
    if (edid.manufactureWeek == kModelYearFlag) {
        info.manufactureOrModelDate = DeviceProductInfo::ModelYear{.year = year};
    } else if (edid.manufactureWeek == 0) {
        DeviceProductInfo::ManufactureYear date;
        date.year = year;
        info.manufactureOrModelDate = date;
    } else {
        DeviceProductInfo::ManufactureWeekAndYear date;
        date.year = year;
        date.week = edid.manufactureWeek;
        info.manufactureOrModelDate = date;
    }

    if (edid.cea861Block && edid.cea861Block->hdmiVendorDataBlock) {
        const auto& address = edid.cea861Block->hdmiVendorDataBlock->physicalAddress;
        info.relativeAddress = {address.a, address.b, address.c, address.d};
    } else {
        info.relativeAddress = DeviceProductInfo::NO_RELATIVE_ADDRESS;
    }
    return info;
}

Cea861ExtensionBlock parseCea861Block(const byte_view& block) {
    Cea861ExtensionBlock cea861Block;

    constexpr size_t kRevisionNumberOffset = 1;
    cea861Block.revisionNumber = block[kRevisionNumberOffset];

    constexpr size_t kDetailedTimingDescriptorsOffset = 2;
    const size_t dtdStart =
            std::min(kEdidBlockSize, static_cast<size_t>(block[kDetailedTimingDescriptorsOffset]));

    // Parse data blocks.
    for (size_t dataBlockOffset = 4; dataBlockOffset < dtdStart;) {
        const uint8_t header = block[dataBlockOffset];
        const uint8_t tag = header >> 5;
        const size_t bodyLength = header & 0b11111;
        constexpr size_t kDataBlockHeaderSize = 1;
        const size_t dataBlockSize = bodyLength + kDataBlockHeaderSize;

        if (block.size() < dataBlockOffset + dataBlockSize) {
            ALOGW("Invalid EDID: CEA 861 data block is truncated.");
            break;
        }

        const byte_view dataBlock(block.data() + dataBlockOffset, dataBlockSize);
        constexpr uint8_t kVendorSpecificDataBlockTag = 0x3;

        if (tag == kVendorSpecificDataBlockTag) {
            const uint32_t ieeeRegistrationId =
                    dataBlock[1] | (dataBlock[2] << 8) | (dataBlock[3] << 16);
            constexpr uint32_t kHdmiIeeeRegistrationId = 0xc03;

            if (ieeeRegistrationId == kHdmiIeeeRegistrationId) {
                const uint8_t a = dataBlock[4] >> 4;
                const uint8_t b = dataBlock[4] & 0b1111;
                const uint8_t c = dataBlock[5] >> 4;
                const uint8_t d = dataBlock[5] & 0b1111;
                cea861Block.hdmiVendorDataBlock =
                        HdmiVendorDataBlock{.physicalAddress = HdmiPhysicalAddress{a, b, c, d}};
            } else {
                ALOGV("Ignoring vendor specific data block for vendor with IEEE OUI %x",
                      ieeeRegistrationId);
            }
        } else {
            ALOGV("Ignoring CEA-861 data block with tag %x", tag);
        }
        dataBlockOffset += bodyLength + kDataBlockHeaderSize;
    }

    return cea861Block;
}

} // namespace

uint16_t DisplayId::manufacturerId() const {
    return static_cast<uint16_t>(value >> 40);
}

DisplayId DisplayId::fromEdid(uint8_t port, uint16_t manufacturerId, uint32_t modelHash) {
    return {(static_cast<Type>(manufacturerId) << 40) | (static_cast<Type>(modelHash) << 8) | port};
}

bool isEdid(const DisplayIdentificationData& data) {
    const uint8_t kMagic[] = {0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0};
    return data.size() >= sizeof(kMagic) &&
            std::equal(std::begin(kMagic), std::end(kMagic), data.begin());
}

std::optional<Edid> parseEdid(const DisplayIdentificationData& edid) {
    if (edid.size() < kEdidBlockSize) {
        ALOGW("Invalid EDID: structure is truncated.");
        // Attempt parsing even if EDID is malformed.
    } else {
        ALOGW_IF(std::accumulate(edid.begin(), edid.begin() + kEdidBlockSize,
                                 static_cast<uint8_t>(0)),
                 "Invalid EDID: structure does not checksum.");
    }

    constexpr size_t kManufacturerOffset = 8;
    if (edid.size() < kManufacturerOffset + sizeof(uint16_t)) {
        ALOGE("Invalid EDID: manufacturer ID is truncated.");
        return {};
    }

    // Plug and play ID encoded as big-endian 16-bit value.
    const uint16_t manufacturerId =
            (edid[kManufacturerOffset] << 8) | edid[kManufacturerOffset + 1];

    const auto pnpId = getPnpId(manufacturerId);
    if (!pnpId) {
        ALOGE("Invalid EDID: manufacturer ID is not a valid PnP ID.");
        return {};
    }

    constexpr size_t kProductIdOffset = 10;
    if (edid.size() < kProductIdOffset + sizeof(uint16_t)) {
        ALOGE("Invalid EDID: product ID is truncated.");
        return {};
    }
    const uint16_t productId = edid[kProductIdOffset] | (edid[kProductIdOffset + 1] << 8);

    constexpr size_t kManufactureWeekOffset = 16;
    if (edid.size() < kManufactureWeekOffset + sizeof(uint8_t)) {
        ALOGE("Invalid EDID: manufacture week is truncated.");
        return {};
    }
    const uint8_t manufactureWeek = edid[kManufactureWeekOffset];
    ALOGW_IF(0x37 <= manufactureWeek && manufactureWeek <= 0xfe,
             "Invalid EDID: week of manufacture cannot be in the range [0x37, 0xfe].");

    constexpr size_t kManufactureYearOffset = 17;
    if (edid.size() < kManufactureYearOffset + sizeof(uint8_t)) {
        ALOGE("Invalid EDID: manufacture year is truncated.");
        return {};
    }
    const uint8_t manufactureOrModelYear = edid[kManufactureYearOffset];
    ALOGW_IF(manufactureOrModelYear <= 0xf,
             "Invalid EDID: model year or manufacture year cannot be in the range [0x0, 0xf].");

    constexpr size_t kDescriptorOffset = 54;
    if (edid.size() < kDescriptorOffset) {
        ALOGE("Invalid EDID: descriptors are missing.");
        return {};
    }

    byte_view view(edid.data(), edid.size());
    view.remove_prefix(kDescriptorOffset);

    std::string_view displayName;
    std::string_view serialNumber;
    std::string_view asciiText;

    constexpr size_t kDescriptorCount = 4;
    constexpr size_t kDescriptorLength = 18;
    static_assert(kDescriptorLength - kEdidHeaderLength < DeviceProductInfo::TEXT_BUFFER_SIZE);

    for (size_t i = 0; i < kDescriptorCount; i++) {
        if (view.size() < kDescriptorLength) {
            break;
        }

        if (const auto type = getEdidDescriptorType(view)) {
            byte_view descriptor(view.data(), kDescriptorLength);
            descriptor.remove_prefix(kEdidHeaderLength);

            switch (*type) {
                case 0xfc:
                    displayName = parseEdidText(descriptor);
                    break;
                case 0xfe:
                    asciiText = parseEdidText(descriptor);
                    break;
                case 0xff:
                    serialNumber = parseEdidText(descriptor);
                    break;
            }
        }

        view.remove_prefix(kDescriptorLength);
    }

    std::string_view modelString = displayName;

    if (modelString.empty()) {
        ALOGW("Invalid EDID: falling back to serial number due to missing display name.");
        modelString = serialNumber;
    }
    if (modelString.empty()) {
        ALOGW("Invalid EDID: falling back to ASCII text due to missing serial number.");
        modelString = asciiText;
    }
    if (modelString.empty()) {
        ALOGE("Invalid EDID: display name and fallback descriptors are missing.");
        return {};
    }

    // Hash model string instead of using product code or (integer) serial number, since the latter
    // have been observed to change on some displays with multiple inputs.
    const uint32_t modelHash = crc32(modelString);

    // Parse extension blocks.
    std::optional<Cea861ExtensionBlock> cea861Block;
    if (edid.size() < kEdidBlockSize) {
        ALOGW("Invalid EDID: block 0 is truncated.");
    } else {
        constexpr size_t kNumExtensionsOffset = 126;
        const size_t numExtensions = edid[kNumExtensionsOffset];
        view = byte_view(edid.data(), edid.size());
        for (size_t blockNumber = 1; blockNumber <= numExtensions; blockNumber++) {
            view.remove_prefix(kEdidBlockSize);
            if (view.size() < kEdidBlockSize) {
                ALOGW("Invalid EDID: block %zu is truncated.", blockNumber);
                break;
            }

            const byte_view block(view.data(), kEdidBlockSize);
            ALOGW_IF(std::accumulate(block.begin(), block.end(), static_cast<uint8_t>(0)),
                     "Invalid EDID: block %zu does not checksum.", blockNumber);
            const uint8_t tag = block[0];

            constexpr uint8_t kCea861BlockTag = 0x2;
            if (tag == kCea861BlockTag) {
                cea861Block = parseCea861Block(block);
            } else {
                ALOGV("Ignoring block number %zu with tag %x.", blockNumber, tag);
            }
        }
    }

    return Edid{.manufacturerId = manufacturerId,
                .productId = productId,
                .pnpId = *pnpId,
                .modelHash = modelHash,
                .displayName = displayName,
                .manufactureOrModelYear = manufactureOrModelYear,
                .manufactureWeek = manufactureWeek,
                .cea861Block = cea861Block};
}

std::optional<PnpId> getPnpId(uint16_t manufacturerId) {
    const char a = getPnpLetter<0>(manufacturerId);
    const char b = getPnpLetter<1>(manufacturerId);
    const char c = getPnpLetter<2>(manufacturerId);
    return a && b && c ? std::make_optional(PnpId{a, b, c}) : std::nullopt;
}

std::optional<PnpId> getPnpId(DisplayId displayId) {
    return getPnpId(displayId.manufacturerId());
}

std::optional<DisplayIdentificationInfo> parseDisplayIdentificationData(
        uint8_t port, const DisplayIdentificationData& data) {
    if (!isEdid(data)) {
        ALOGE("Display identification data has unknown format.");
        return {};
    }

    const auto edid = parseEdid(data);
    if (!edid) {
        return {};
    }

    const auto displayId = DisplayId::fromEdid(port, edid->manufacturerId, edid->modelHash);
    return DisplayIdentificationInfo{.id = displayId,
                                     .name = std::string(edid->displayName),
                                     .deviceProductInfo = buildDeviceProductInfo(*edid)};
}

DisplayId getFallbackDisplayId(uint8_t port) {
    return DisplayId::fromEdid(port, kFallbackEdidManufacturerId, 0);
}

DisplayId getVirtualDisplayId(uint32_t id) {
    return DisplayId::fromEdid(0, kVirtualEdidManufacturerId, id);
}

} // namespace android

// TODO(b/129481165): remove the #pragma below and fix conversion issues
#pragma clang diagnostic pop // ignored "-Wconversion"
