/*
 * Copyright 2019 The Android Open Source Project
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

#pragma once

#include <android/hardware/graphics/mapper/4.0/IMapper.h>

namespace android {

namespace gralloc4 {

const std::string COMMON = "Gralloc4Common";

/*---------------------------------------------------------------------------------------------*/
/**
 * This file contains IMapper@4.x types. For more details, see IMapper@4.0.
 */
/*---------------------------------------------------------------------------------------------*/

/**
 * The struct below is defined in IMapper@4.0. It is re-written here for documentation purposes.
 *
 * BufferMetadataType represents the different types of buffer metadata that could be associated
 * with a buffer. It is used by IMapper to help get and set buffer metadata on the buffer's native
 * handle.
 *
 * Common buffer metadata will have the company name set to "Gralloc4Common" and will
 * contain values from BufferMetadataTypeCommon.
 *
 * This struct should be "extended" by devices that use a proprietary or non-standard buffer
 * metadata. To extend the struct, the company name should be set to the name of the company who is
 * adding the new compression strategy. Each company should define and version its own values. The
 * company name field prevents values from different companies from colliding.
 */
// struct BufferMetadataType {
//     string company;
//     uint64_t value;
// };

/* Typedef the HIDL struct to match the same naming pattern as the rest of the file. */
using BufferMetadataType = ::android::hardware::graphics::mapper::V4_0::IMapper::BufferMetadataType;

/**
 * BufferMetadataTypeCommon is an enum that defines the common types of gralloc 4
 * buffer metadata. The comments for each enum include a description of the metadata
 * that is associated with the type.
 *
 * IMapper@4.x must support getting the following common buffer metadata types. IMapper@4.x may
 * support setting these common buffer metadata types as well.
 */
enum BufferMetadataTypeCommon : uint32_t {
    /**
     * Can be used to get the random ID of the buffer. This ID should be psuedorandom with
     * sufficient entropy.
     *
     * This ID should only be used for debugging purposes. It cannot be used as a basis for any
     * control flows.
     *
     * The buffer ID is determined at allocation time and should not change during the lifetime
     * of the buffer.
     *
     * The buffer ID is a uint64_t.
     */
    BUFFER_ID,

    /**
     * Can be used to get the name passed in by the client at allocation time in the
     * BufferDescriptorInfo.
     *
     * The buffer name is determined at allocation time and should not change during the lifetime
     * of the buffer.
     *
     * The buffer name is a C style string. It is an array of chars followed by a null terminator.
     */
    NAME,

    /**
     * Can be used to get the number of elements per buffer row requested at allocation time in
     * the BufferDescriptorInfo.
     *
     * The width is determined at allocation time and should not change during the lifetime
     * of the buffer.
     *
     * The width is a uint64_t.
     */
    WIDTH,

    /**
     * Can be used to get the number of elements per buffer column requested at allocation time in
     * the BufferDescriptorInfo.
     *
     * The height is determined at allocation time and should not change during the lifetime
     * of the buffer.
     *
     * The height is a uint64_t.
     */
    HEIGHT,

    /**
     * Can be used to get the number of layers requested at allocation time in the
     * BufferDescriptorInfo.
     *
     * The layer count is determined at allocation time and should not change during the lifetime
     * of the buffer.
     *
     * The layer count is a uint64_t.
     */
    LAYER_COUNT,

    /**
     * Can be used to get the buffer format requested at allocation time in the
     * BufferDescriptorInfo.
     *
     * The requested pixel format is determined at allocation time and should not change during
     * the lifetime of the buffer.
     *
     * The requested pixel format is a uint64_t.
     */
    PIXEL_FORMAT_REQUESTED,

    /**
     * Can be used to get the fourcc code for the format. Fourcc codes are standard across all
     * devices of the same kernel version. Fourcc codes must follow the Linux definition of a
     * fourcc format found in: include/uapi/drm/drm_fourcc.h.
     *
     * The pixel format fourcc code is represented by a uint32_t.
     */
    PIXEL_FORMAT_FOURCC,

    /**
     * Can be used to get the modifier for the format. Together fourcc and modifier describe the
     * real pixel format. Each fourcc and modifier pair is unique and must fully define the format
     * and layout of the buffer. Modifiers can change any property of the buffer. Modifiers must
     * follow the Linux definiton of a modifier found in: include/uapi/drm/drm_fourcc.h.
     *
     * The pixel format modifier is represented by a uint64_t.
     */
    PIXEL_FORMAT_MODIFIER,

    /**
     * Can be used to get the usage requested at allocation time in the BufferDescriptorInfo.
     *
     * The usage is determined at allocation time and should not change during the lifetime
     * of the buffer.
     *
     * The usage is a uint64_t bit field of android.hardware.graphics.common@1.2::BufferUsage.
     */
    USAGE,

    /**
     * Can be used to get the total size in bytes of any memory used by the buffer including its
     * metadata and extra padding. This is the total number of bytes used by the buffer allocation.
     *
     * The allocation size is a uint64_t.
     */
    ALLOCATION_SIZE,

    /**
     * Can be used to get if a buffer has protected content. If the buffer does not have protected
     * content, this should return 0. If a buffer has protected content, this should return 1.
     *
     * The protected content is a uint64_t.
     */
    PROTECTED_CONTENT,

    /**
     * Can be used to get the compression strategy of the buffer. If the device has more than one
     * compression strategy, it should have different unique values for each compression
     * strategy.
     *
     * The compression strategy is a CompressionStrategy.
     */
    COMPRESSION_STRATEGY,

    /**
     * Can be used to get how the buffer's planes are interlaced.
     *
     * The interlaced strategy is a InterlacedStrategy.
     */
    INTERLACED_STRATEGY,

    /**
     * Can be used to get the chroma siting of a buffer.
     *
     * The chroma siting is a ChromaSiting.
     */
    CHROMA_SITING,

    /**
     * Can be used to get the PlaneLayout(s) of the buffer. There should be one PlaneLayout per
     * plane in the buffer. For example if the buffer only has one plane, only one PlaneLayout
     * should be returned.
     *
     * If the buffer has planes interlaced through time, the returned PlaneLayout structs should be
     * ordered by time. The nth PlaneLayout should be from the same time or earlier than the
     * n+1 PlaneLayout.
     */
    PLANE_LAYOUTS,

    /**
     * Can be used to get or set the dataspace of the buffer. The framework may attempt to set
     * this value.
     *
     * The default dataspace is Dataspace::UNKNOWN. If this dataspace is set to any valid value
     * other than Dataspace::UNKNOWN, this dataspace overrides all other dataspaces. For example,
     * if the buffer has Dataspace::DISPLAY_P3 and it is being displayed on a composer Layer that
     * is Dataspace::sRGB, the buffer should be treated as a DISPLAY_P3 buffer.
     *
     * The dataspace is a android.hardware.graphics.common@1.2::Dataspace.
     */
    DATASPACE,

    /**
     * Can be used to get or set the PerFrameMetadata or PerFrameMetadataBlob. The framework may
     * attempt to set these values.
     *
     * The default values of PerFrameMetadata and PerFrameMetadataBlob are an empty vec<uint8_t>.
     * In the default case, the get()/getFromBufferDescriptorInfo() calls should generate an empty
     * vec<uint8_t> and return Error::NONE. Calling set() with an empty vec<uint8_t> resets the
     * field back to its default value.
     *
     * If either of the PerFrameMetadata and PerFrameMetadataBlob are set to non-default values,
     * they override all other PerFrameMetadata and PerFrameMetadataBlobs. For a longer
     * description of this behavior see BufferMetadataType::DATASPACE.
     *
     * The per frame metadata is a android.hardware.graphics.composer@2.2::PerFrameMetadata.
     * The per frame metadata blob is a android.hardware.graphics.composer@2.3::PerFrameMetadataBlob
     */
    PER_FRAME_METADATA,
    PER_FRAME_METADATA_BLOB,

    /**
     * Can be used to get or set the BlendMode. The framework may attempt to set this value.
     *
     * The default blend mode is BlendMode::INVALID. If the BlendMode is set to any valid value
     * other than BlendMode::INVALID, this BlendMode overrides all other dataspaces. For a longer
     * description of this behavior see BufferMetadataType::DATASPACE.
     *
     * The blend mode is a android.hardware.graphics.composer@2.1::BlendMode.
     */
    BLEND_MODE,
};

/**
 * Definitions of the common buffer metadata types. It is recommended that everyone uses
 * these definitions directly for common buffer metadata types.
 */
static const BufferMetadataType BufferMetadataType_BufferId = {
        COMMON, BufferMetadataTypeCommon::BUFFER_ID
};

static const BufferMetadataType BufferMetadataType_Name = {
        COMMON, BufferMetadataTypeCommon::NAME
};

static const BufferMetadataType BufferMetadataType_Width = {
        COMMON, BufferMetadataTypeCommon::WIDTH
};

static const BufferMetadataType BufferMetadataType_Height = {
        COMMON, BufferMetadataTypeCommon::HEIGHT
};

static const BufferMetadataType BufferMetadataType_LayerCount = {
        COMMON, BufferMetadataTypeCommon::LAYER_COUNT
};

static const BufferMetadataType BufferMetadataType_PixelFormatRequested = {
        COMMON, BufferMetadataTypeCommon::PIXEL_FORMAT_REQUESTED
};

static const BufferMetadataType BufferMetadataType_PixelFormatFourcc = {
        COMMON, BufferMetadataTypeCommon::PIXEL_FORMAT_FOURCC
};

static const BufferMetadataType BufferMetadataType_PixelFormatModifier = {
        COMMON, BufferMetadataTypeCommon::PIXEL_FORMAT_MODIFIER
};

static const BufferMetadataType BufferMetadataType_Usage = {
        COMMON, BufferMetadataTypeCommon::USAGE
};

static const BufferMetadataType BufferMetadataType_AllocationSize = {
        COMMON, BufferMetadataTypeCommon::ALLOCATION_SIZE
};

static const BufferMetadataType BufferMetadataType_ProtectedContent = {
        COMMON, BufferMetadataTypeCommon::PROTECTED_CONTENT
};

static const BufferMetadataType BufferMetadataType_CompressionStrategy = {
        COMMON, BufferMetadataTypeCommon::COMPRESSION_STRATEGY
};

static const BufferMetadataType BufferMetadataType_InterlacedStrategy = {
        COMMON, BufferMetadataTypeCommon::INTERLACED_STRATEGY
};

static const BufferMetadataType BufferMetadataType_ChromaSiting = {
        COMMON, BufferMetadataTypeCommon::CHROMA_SITING
};

static const BufferMetadataType BufferMetadataType_PlaneLayouts = {
        COMMON, BufferMetadataTypeCommon::PLANE_LAYOUTS
};

static const BufferMetadataType BufferMetadataType_Dataspace = {
        COMMON, BufferMetadataTypeCommon::DATASPACE
};

static const BufferMetadataType BufferMetadataType_PerFrameMetadata = {
        COMMON, BufferMetadataTypeCommon::PER_FRAME_METADATA
};

static const BufferMetadataType BufferMetadataType_PerFrameMetadataBlob = {
        COMMON, BufferMetadataTypeCommon::PER_FRAME_METADATA_BLOB
};

static const BufferMetadataType BufferMetadataType_BlendMode = {
        COMMON, BufferMetadataTypeCommon::BLEND_MODE
};

/*---------------------------------------------------------------------------------------------*/

/**
 * Describes the compression strategy of the buffer. Common compression strategies will have the
 * company name set to "Gralloc4Common" and will contain values from
 * CompressionStrategyCommon.
 *
 * This struct should be extended by devices that use proprietary or non-standard compression
 * strategies. For extensions, the company name should be set to the name of the company who is
 * adding the new compression strategy. Each company should define and version its own values. The
 * company name field prevents values from different companies from colliding.
 */
struct CompressionStrategy {
    std::string company;
    uint64_t value;
};

/**
 * Enum that describes common compression strategies.
 */
enum CompressionStrategyCommon : uint64_t {
    /* Represents all uncompressed buffers */
    UNCOMPRESSED,

    /* VESA Display Stream Compression (DSC) */
    DISPLAY_STREAM_COMPRESSION,
};

/**
 * Definitions of the common compression strategies. It is recommended that everyone uses
 * these definitions directly for common compression strategies.
 */
static const CompressionStrategy CompressionStrategy_Uncompressed = {
        COMMON, CompressionStrategyCommon::UNCOMPRESSED
};

static const CompressionStrategy CompressionStrategy_DisplayStreamCompression = {
        COMMON, CompressionStrategyCommon::DISPLAY_STREAM_COMPRESSION
};

/*---------------------------------------------------------------------------------------------*/

/**
 * Describes the interlaced strategy of the buffer. Common interlaced strategies will have the
 * company name set to "Gralloc4Common" and will contain values from
 * InterlacedStrategyCommon.
 *
 * This struct should be extended by devices that use proprietary or non-standard interlaced
 * strategies. For extensions, the company name should be set to the name of the company who is
 * adding the new interlaced strategy. Each company should define and version its own values. The
 * company name field prevents values from different companies from colliding.
 */
struct InterlacedStrategy {
    std::string company;
    uint64_t value;
};

/**
 * Enum that describes how the buffer's planes are commonly interlaced. This enum is used when
 * the planes inside a buffer are interlaced. This enum is not used to describe interlacing
 * between seperate buffers.
 */
enum InterlacedStrategyCommon : uint64_t {
    /* The buffer is not interlaced. */
    NONE,

    /* The buffer's planes are interlaced horizontally. The height of each interlaced plane is
     * 1/2 the height of the buffer's height. */
    TOP_BOTTOM,

    /* The buffer's planes are interlaced vertically. The width of each interlaced plane is
     * 1/2 the width of the buffer's width. */
    RIGHT_LEFT,
};

/**
 * Definitions of the common interlaced strategies. It is recommended that everyone uses
 * these definitions directly for common interlaced strategies.
 */
static const InterlacedStrategy InterlacedStrategy_None = {
        COMMON, InterlacedStrategyCommon::NONE
};

static const InterlacedStrategy InterlacedStrategy_TopBottom = {
        COMMON, InterlacedStrategyCommon::TOP_BOTTOM
};

static const InterlacedStrategy InterlacedStrategy_RightLeft = {
        COMMON, InterlacedStrategyCommon::RIGHT_LEFT
};

/*---------------------------------------------------------------------------------------------*/

/**
 * Describes the chroma siting of the buffer. Common chroma sitings will have the
 * company name set to "Gralloc4Common" and will contain values from
 * ChromaSitingCommon.
 *
 * This struct should be extended by devices that use a proprietary or non-standard chroma sitings
 * For extensions, the company name should be set to the name of the company who is adding
 * the new chroma siting. Each company should define and version its own values. The company
 * name field prevents values from different companies from colliding.
 */
struct ChromaSiting {
    std::string company;
    uint64_t value;
};

/**
 * Enum that describes common chroma sitings.
 */
enum ChromaSitingCommon : uint64_t {
    /* This format does not have chroma siting. */
    NOT_APPLICABLE,

    /* This format has chroma siting but the type being used is unknown. */
    UNKNOWN,

    /* Cb and Cr are sited interstitially, halfway between alternate luma samples.
     * This is used by 4:2:0 for JPEG/JFIF, H.261, MPEG-1. */
    SITED_INTERSTITIAL,

    /* Cb and Cr are horizontally sited coincident with a luma sample.
     * Cb and Cr are vertically sited interstitially.
     * This is used by 4:2:0 for MPEG-2 frame pictures. */
    COSITED_HORIZONTAL,
};

/**
 * Definitions of the common chroma siting. It is recommended that everyone uses
 * these definitions directly for common chroma siting.
 */
static const ChromaSiting ChromaSiting_NotApplicable = {
        COMMON, ChromaSitingCommon::NOT_APPLICABLE
};

static const ChromaSiting ChromaSiting_Unknown = {
        COMMON, ChromaSitingCommon::UNKNOWN
};

static const ChromaSiting ChromaSiting_SitedInterstitial = {
        COMMON, ChromaSitingCommon::SITED_INTERSTITIAL
};

static const ChromaSiting ChromaSiting_CositedHorizontal = {
        COMMON, ChromaSitingCommon::COSITED_HORIZONTAL
};

/*---------------------------------------------------------------------------------------------*/

struct PlaneLayoutComponentType;
struct PlaneLayoutComponent;

/**
 * Describes a plane's layout.
 *
 * PlaneLayout uses the following terms and definitions:
 *
 * - Component - a component is one channel of a pixel. For example, an RGBA format has
 *      four components: R, G, B and A.
 * - Sample - a sample is comprised of all the components in a given plane. For example,
 *      a buffer with one Y plane and one CbCr plane has one plane with a sample of Y
 *      and one plane with a sample of CbCr.
 * - Pixel - a pixel is comprised of all the (non-metadata/raw) components in buffer across
 *      all planes. For example, a buffer with a plane of Y and a plane of CbCr has a pixel
 *      of YCbCr.
 */
struct PlaneLayout {
    /**
     * Offset to the first byte of the plane (in bytes), from the start of the allocation.
     */
    uint64_t offsetInBytes;

    /**
     * A vector of plane layout components. This list of components should include
     * every component in this plane. For example, a CbCr plane should return a
     * vector of size two with one PlaneLayoutComponent for Cb and one for Cr.
     */
    std::vector<PlaneLayoutComponent> components;

    /**
     * Bits per sample increment (aka column increment or row stride): describes the distance
     * in bits from one sample to the next sample (to the right) on the same row for the
     * the component plane.
     *
     * The default value is 0. Return the default value if the increment is undefined, unknown,
     * or variable.
     *
     * This can be negative. A negative increment indicates that the samples are read from
     * right to left.
     */
    int64_t bitsPerSampleIncrement;

    /**
     * Bytes per Stride: number of bytes between two vertically adjacent
     * samples in given plane. This can be mathematically described by:
     *
     * bytesPerStride = ALIGN(allocationWidth * bps / 8, alignment)
     *
     * where,
     *
     * allocationWidth: width of plane in samples
     * bps: average bits per sample
     * alignment (in bytes): dependent upon pixel format and usage
     *
     * bytesPerStride can contain additional padding beyond the allocationWidth.
     *
     * The default value is 0. Return the default value if the stride is undefined, unknown,
     * or variable.
     *
     * This can be negative. A negative stride indicates that the rows are read from
     * bottom to top.
     */
    int64_t bytesPerStride;

    /**
     * Dimensions of plane (in samples).
     *
     * This is the number of samples in the plane, even if subsampled.
     *
     * See 'bytesPerStride' for relationship between bytesPerStride and allocationWidth.
     */
    uint64_t allocationWidth;
    uint64_t allocationHeight;

    /**
     * Can be used to get the total size in bytes of any memory used by the plane
     * including metadata and extra padding.
     */
    uint64_t allocationSize;

    /**
     * Horizontal and vertical subsampling. Must be a positive power of 2.
     */
    int64_t horizontalSubsampling;
    int64_t verticalSubsampling;

    /**
     * Some buffer producers require extra padding to their output buffer; therefore the
     * physical size of the native buffer will be larger than its logical size.
     * The crop rectangle determines the offset and logical size of the buffer that should be
     * read by consumers.
     *
     * The crop rectangle is measured in samples and is relative to the offset of the
     * plane. Valid crop rectangles are within the boundaries of the plane:
     * [0, 0, allocationWidth, allocationHeight].
     *
     * The framework will NOT try to set this value.
     *
     * The default crop rectangle is a rectangle the same size as the plane:
     * [0, 0, allocationWidth, allocationHeight].
     */
    android::hardware::graphics::mapper::V4_0::IMapper::Rect cropRectangle;
};

/*---------------------------------------------------------------------------------------------*/

/**
 * Describes the plane layout component type of the buffer. Common plane layout component types will
 * have the company name set to "Gralloc4Common" and will contain values from
 * PlaneLayoutComponentTypeCommon.
 *
 * This struct should be extended by devices that use proprietary or non-standard plane layout
 * component types. For extensions, the company name should be set to the name of the company who is
 * adding the new plane layout component type. Each company should define and version its own
 * values. The company name field prevents values from different companies from colliding.
 */
struct PlaneLayoutComponentType {
    std::string company;
    uint64_t value;
};

/**
 * Enums that describes the type of a given PlaneLayoutComponent.
 */
enum PlaneLayoutComponentTypeCommon : uint64_t {
    /* Luma */
    PLANE_LAYOUT_COMPONENT_Y,
    /* Chroma blue */
    PLANE_LAYOUT_COMPONENT_Cb,
    /* Chroma red */
    PLANE_LAYOUT_COMPONENT_Cr,

    /* Red */
    PLANE_LAYOUT_COMPONENT_R,
    /* Green */
    PLANE_LAYOUT_COMPONENT_G,
    /* Blue */
    PLANE_LAYOUT_COMPONENT_B,
    /* Alpha */
    PLANE_LAYOUT_COMPONENT_A,

    /* Metadata */
    PLANE_LAYOUT_COMPONENT_METADATA,
    /* Raw */
    PLANE_LAYOUT_COMPONENT_RAW,
};

/**
 * Definitions of the common plane layout component types. It is recommended that everyone uses
 * these definitions directly for common plane layout component types
 */
static const uint64_t PlaneLayoutComponentType_Y =
        PlaneLayoutComponentTypeCommon::PLANE_LAYOUT_COMPONENT_Y;

static const uint64_t PlaneLayoutComponentType_Cb =
        PlaneLayoutComponentTypeCommon::PLANE_LAYOUT_COMPONENT_Cb;

static const uint64_t PlaneLayoutComponentType_Cr =
        PlaneLayoutComponentTypeCommon::PLANE_LAYOUT_COMPONENT_Cr;

static const uint64_t PlaneLayoutComponentType_R =
        PlaneLayoutComponentTypeCommon::PLANE_LAYOUT_COMPONENT_R;

static const uint64_t PlaneLayoutComponentType_G =
        PlaneLayoutComponentTypeCommon::PLANE_LAYOUT_COMPONENT_G;

static const uint64_t PlaneLayoutComponentType_B =
        PlaneLayoutComponentTypeCommon::PLANE_LAYOUT_COMPONENT_B;

static const uint64_t PlaneLayoutComponentType_Metadata =
        PlaneLayoutComponentTypeCommon::PLANE_LAYOUT_COMPONENT_METADATA;

static const uint64_t PlaneLayoutComponentType_Raw =
        PlaneLayoutComponentTypeCommon::PLANE_LAYOUT_COMPONENT_RAW;

static const uint64_t PlaneLayoutComponentType_A =
        PlaneLayoutComponentTypeCommon::PLANE_LAYOUT_COMPONENT_A;

/*---------------------------------------------------------------------------------------------*/

/**
 * Describes the type and location of a component in a plane.
 */
struct PlaneLayoutComponent {
    /**
     * The type of this plane layout component.
     */
    PlaneLayoutComponentType type;

    /**
     * Offset in bits to the first instance of this component in the plane.
     * This is relative to the plane's offset (PlaneLayout::offset).
     *
     * If the offset cannot be described using a int64_t, this should be set to -1.
     * For example, if the plane is compressed and the offset is not defined or
     * relevant, return -1.
     */
    int64_t offsetInBits;

    /**
     * The number of bits used per component in the plane.
     *
     * If the plane layout component cannot be described using bitsPerComponent, this
     * should be set to -1. For example, if the component varies in size throughout
     * the plane, return -1.
     */
    int64_t bitsPerComponent;
};

/*---------------------------------------------------------------------------------------------*/

} // namespace gralloc4

} // namespace android
