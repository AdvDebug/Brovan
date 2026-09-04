using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// Stands in for textureCompressionBC. A BCn image becomes an uncompressed image of the same extent, and
    /// each buffer-to-image copy into it becomes a compute dispatch that decodes the blocks into that image.
    /// </summary>
    internal static unsafe class TextureCompressionBC
    {
        internal const int FormatR8Uint = 13;
        internal const int FormatRg8Uint = 20;
        internal const uint FormatFeatureStorageImage = 0x2;

        private const int FormatR8Unorm = 9;
        private const int FormatR8Snorm = 10;
        private const int FormatRg8Unorm = 16;
        private const int FormatRg8Snorm = 17;
        private const int FormatRgba8Unorm = 37;
        private const int FormatRgba8Snorm = 38;
        private const int FormatRgba8Uint = 41;
        private const int FormatRgba8Srgb = 43;
        private const int FormatRgba16Uint = 95;
        private const int FormatRgba16Sfloat = 97;
        private const int FormatBc1RgbUnorm = 131;
        private const int FormatBc4Unorm = 139;
        private const int FormatBc4Snorm = 140;
        private const int FormatBc5Unorm = 141;
        private const int FormatBc5Snorm = 142;
        private const int FormatBc6hUfloat = 143;
        private const int FormatBc6hSfloat = 144;
        private const int FormatBc7Srgb = 146;

        private const uint StImageViewCreateInfo = 15;
        private const uint StShaderModuleCreateInfo = 16;
        private const uint StPipelineShaderStageCreateInfo = 18;
        private const uint StComputePipelineCreateInfo = 29;
        private const uint StPipelineLayoutCreateInfo = 30;
        private const uint StDescriptorSetLayoutCreateInfo = 32;
        private const uint StDescriptorPoolCreateInfo = 33;
        private const uint StDescriptorSetAllocateInfo = 34;
        private const uint StWriteDescriptorSet = 35;
        private const uint StImageMemoryBarrier = 45;
        private const uint StMemoryBarrier = 46;
        private const uint StFormatProperties2 = 1000059002;
        private const uint StImageViewUsageCreateInfo = 1000117002;
        private const uint StImageFormatListCreateInfo = 1000147000;
        private const uint StFormatProperties3 = 1000360000;
        private const uint StBufferUsageFlags2CreateInfo = 1000470006;

        private const uint ImageCreateMutableFormat = 0x8;
        private const uint ImageCreate2DArrayCompatible = 0x20;
        private const uint ImageCreateBlockTexelViewCompatible = 0x80;
        private const uint ImageCreateExtendedUsage = 0x100;
        private const uint ImageUsageTransferSrc = 0x1;
        private const uint ImageUsageStorage = 0x8;
        private const uint BufferUsageTransferSrc = 0x1;
        private const uint BufferUsageStorage = 0x20;
        private const int ImageTilingOptimal = 0;
        private const int ImageType3D = 2;
        private const int ImageViewType2DArray = 5;
        private const uint ImageAspectColor = 1;
        private const int ImageLayoutGeneral = 1;
        private const int DescriptorTypeStorageImage = 3;
        private const int DescriptorTypeStorageBuffer = 7;
        private const uint ShaderStageCompute = 0x20;
        private const int PipelineBindPointCompute = 1;
        private const uint PipelineStageComputeShader = 0x800;
        private const uint PipelineStageAllCommands = 0x10000;
        private const uint AccessShaderRead = 0x20;
        private const uint AccessShaderWrite = 0x40;
        private const uint AccessMemoryRead = 0x8000;
        private const uint AccessMemoryWrite = 0x10000;
        private const uint QueueCompute = 2;
        private const uint QueueFamilyIgnored = 0xFFFFFFFFu;
        private const ulong WholeSize = ulong.MaxValue;
        private const int ErrorFormatNotSupported = -11;

        private const uint ModePunchThrough = 0x10;
        private const uint ModeSigned = 0x20;
        private const int PushBytes = 40;
        private const int PoolSets = 128;
        private const int MaxReplayCalls = 32;
        private const int MaxPushBytes = 256;

        // The optimal tiling features a BCn format may claim: whatever the substitute has of these.
        private const uint AdvertisedFeatures = 0x1 | 0x400 | 0x1000 | 0x2000 | 0x4000 | 0x8000 | 0x10000;

        private const string ResourcePrefix = "VulkanImpls.bcdecode_";
        private static readonly string[] VariantNames = { "rgba8", "rg8", "r8", "rgba16" };
        private static readonly byte[]?[] VariantCode = new byte[]?[4];

        private static readonly int[] Rgba8Views = { FormatRgba8Unorm, FormatRgba8Srgb, FormatRgba8Snorm, FormatRgba8Uint };
        private static readonly int[] R8Views = { FormatR8Unorm, FormatR8Snorm, FormatR8Uint };
        private static readonly int[] Rg8Views = { FormatRg8Unorm, FormatRg8Snorm, FormatRg8Uint };
        private static readonly int[] Rgba16Views = { FormatRgba16Sfloat, FormatRgba16Uint };

        private static readonly HashSet<string> Reported = new HashSet<string>();

        private static class L
        {
            internal static readonly int ImageFlags = BrovVulkLayout.MemberOffset["VkImageCreateInfo.flags"];
            internal static readonly int ImageType = BrovVulkLayout.MemberOffset["VkImageCreateInfo.imageType"];
            internal static readonly int ImageFormat = BrovVulkLayout.MemberOffset["VkImageCreateInfo.format"];
            internal static readonly int ImageExtent = BrovVulkLayout.MemberOffset["VkImageCreateInfo.extent"];
            internal static readonly int ImageMipLevels = BrovVulkLayout.MemberOffset["VkImageCreateInfo.mipLevels"];
            internal static readonly int ImageArrayLayers = BrovVulkLayout.MemberOffset["VkImageCreateInfo.arrayLayers"];
            internal static readonly int ImageTiling = BrovVulkLayout.MemberOffset["VkImageCreateInfo.tiling"];
            internal static readonly int ImageUsage = BrovVulkLayout.MemberOffset["VkImageCreateInfo.usage"];

            internal static readonly int FormatListSize = BrovVulkLayout.StructSize["VkImageFormatListCreateInfo"];
            internal static readonly int FormatListCount = BrovVulkLayout.MemberOffset["VkImageFormatListCreateInfo.viewFormatCount"];
            internal static readonly int FormatListFormats = BrovVulkLayout.MemberOffset["VkImageFormatListCreateInfo.pViewFormats"];

            internal static readonly int ViewSize = BrovVulkLayout.StructSize["VkImageViewCreateInfo"];
            internal static readonly int ViewImage = BrovVulkLayout.MemberOffset["VkImageViewCreateInfo.image"];
            internal static readonly int ViewType = BrovVulkLayout.MemberOffset["VkImageViewCreateInfo.viewType"];
            internal static readonly int ViewFormat = BrovVulkLayout.MemberOffset["VkImageViewCreateInfo.format"];
            internal static readonly int ViewRange = BrovVulkLayout.MemberOffset["VkImageViewCreateInfo.subresourceRange"];
            internal static readonly int ViewUsageSize = BrovVulkLayout.StructSize["VkImageViewUsageCreateInfo"];
            internal static readonly int ViewUsageUsage = BrovVulkLayout.MemberOffset["VkImageViewUsageCreateInfo.usage"];

            internal static readonly int BufferUsage = BrovVulkLayout.MemberOffset["VkBufferCreateInfo.usage"];
            internal static readonly int BufferUsage2 = BrovVulkLayout.MemberOffset["VkBufferUsageFlags2CreateInfo.usage"];

            internal static readonly int FormatPropertiesSize = BrovVulkLayout.StructSize["VkFormatProperties"];
            internal static readonly int FormatLinear = BrovVulkLayout.MemberOffset["VkFormatProperties.linearTilingFeatures"];
            internal static readonly int FormatOptimal = BrovVulkLayout.MemberOffset["VkFormatProperties.optimalTilingFeatures"];
            internal static readonly int FormatBuffer = BrovVulkLayout.MemberOffset["VkFormatProperties.bufferFeatures"];
            internal static readonly int FormatProperties2Size = BrovVulkLayout.StructSize["VkFormatProperties2"];
            internal static readonly int FormatProperties2Body = BrovVulkLayout.MemberOffset["VkFormatProperties2.formatProperties"];
            internal static readonly int FormatProperties3Size = BrovVulkLayout.StructSize["VkFormatProperties3"];
            internal static readonly int Format3Linear = BrovVulkLayout.MemberOffset["VkFormatProperties3.linearTilingFeatures"];
            internal static readonly int Format3Optimal = BrovVulkLayout.MemberOffset["VkFormatProperties3.optimalTilingFeatures"];
            internal static readonly int Format3Buffer = BrovVulkLayout.MemberOffset["VkFormatProperties3.bufferFeatures"];

            internal static readonly int ImageFormatInfoFormat = BrovVulkLayout.MemberOffset["VkPhysicalDeviceImageFormatInfo2.format"];
            internal static readonly int ImageFormatInfoType = BrovVulkLayout.MemberOffset["VkPhysicalDeviceImageFormatInfo2.type"];
            internal static readonly int ImageFormatInfoTiling = BrovVulkLayout.MemberOffset["VkPhysicalDeviceImageFormatInfo2.tiling"];
            internal static readonly int ImageFormatInfoUsage = BrovVulkLayout.MemberOffset["VkPhysicalDeviceImageFormatInfo2.usage"];
            internal static readonly int ImageFormatInfoFlags = BrovVulkLayout.MemberOffset["VkPhysicalDeviceImageFormatInfo2.flags"];

            internal static readonly int CopySource = BrovVulkLayout.MemberOffset["VkCopyBufferToImageInfo2.srcBuffer"];
            internal static readonly int CopyDestination = BrovVulkLayout.MemberOffset["VkCopyBufferToImageInfo2.dstImage"];
            internal static readonly int CopyLayout = BrovVulkLayout.MemberOffset["VkCopyBufferToImageInfo2.dstImageLayout"];
            internal static readonly int CopyRegionCount = BrovVulkLayout.MemberOffset["VkCopyBufferToImageInfo2.regionCount"];
            internal static readonly int CopyRegions = BrovVulkLayout.MemberOffset["VkCopyBufferToImageInfo2.pRegions"];

            internal static readonly int SubresourceAspect = BrovVulkLayout.MemberOffset["VkImageSubresourceLayers.aspectMask"];
            internal static readonly int SubresourceLevel = BrovVulkLayout.MemberOffset["VkImageSubresourceLayers.mipLevel"];
            internal static readonly int SubresourceLayer = BrovVulkLayout.MemberOffset["VkImageSubresourceLayers.baseArrayLayer"];
            internal static readonly int SubresourceLayers = BrovVulkLayout.MemberOffset["VkImageSubresourceLayers.layerCount"];

            internal static readonly int LayoutBindingSize = BrovVulkLayout.StructSize["VkDescriptorSetLayoutBinding"];
            internal static readonly int LayoutBindingBinding = BrovVulkLayout.MemberOffset["VkDescriptorSetLayoutBinding.binding"];
            internal static readonly int LayoutBindingType = BrovVulkLayout.MemberOffset["VkDescriptorSetLayoutBinding.descriptorType"];
            internal static readonly int LayoutBindingCount = BrovVulkLayout.MemberOffset["VkDescriptorSetLayoutBinding.descriptorCount"];
            internal static readonly int LayoutBindingStages = BrovVulkLayout.MemberOffset["VkDescriptorSetLayoutBinding.stageFlags"];
            internal static readonly int SetLayoutSize = BrovVulkLayout.StructSize["VkDescriptorSetLayoutCreateInfo"];
            internal static readonly int SetLayoutBindingCount = BrovVulkLayout.MemberOffset["VkDescriptorSetLayoutCreateInfo.bindingCount"];
            internal static readonly int SetLayoutBindings = BrovVulkLayout.MemberOffset["VkDescriptorSetLayoutCreateInfo.pBindings"];
            internal static readonly int PushRangeSize = BrovVulkLayout.StructSize["VkPushConstantRange"];
            internal static readonly int PushRangeStages = BrovVulkLayout.MemberOffset["VkPushConstantRange.stageFlags"];
            internal static readonly int PushRangeOffset = BrovVulkLayout.MemberOffset["VkPushConstantRange.offset"];
            internal static readonly int PushRangeSizeMember = BrovVulkLayout.MemberOffset["VkPushConstantRange.size"];
            internal static readonly int PipelineLayoutSize = BrovVulkLayout.StructSize["VkPipelineLayoutCreateInfo"];
            internal static readonly int PipelineLayoutSetCount = BrovVulkLayout.MemberOffset["VkPipelineLayoutCreateInfo.setLayoutCount"];
            internal static readonly int PipelineLayoutSets = BrovVulkLayout.MemberOffset["VkPipelineLayoutCreateInfo.pSetLayouts"];
            internal static readonly int PipelineLayoutPushCount = BrovVulkLayout.MemberOffset["VkPipelineLayoutCreateInfo.pushConstantRangeCount"];
            internal static readonly int PipelineLayoutPushRanges = BrovVulkLayout.MemberOffset["VkPipelineLayoutCreateInfo.pPushConstantRanges"];
            internal static readonly int ComputePipelineSize = BrovVulkLayout.StructSize["VkComputePipelineCreateInfo"];
            internal static readonly int ComputePipelineStage = BrovVulkLayout.MemberOffset["VkComputePipelineCreateInfo.stage"];
            internal static readonly int ComputePipelineLayout = BrovVulkLayout.MemberOffset["VkComputePipelineCreateInfo.layout"];
            internal static readonly int ComputePipelineBaseIndex = BrovVulkLayout.MemberOffset["VkComputePipelineCreateInfo.basePipelineIndex"];

            internal static readonly int PoolSizeSize = BrovVulkLayout.StructSize["VkDescriptorPoolSize"];
            internal static readonly int PoolSizeType = BrovVulkLayout.MemberOffset["VkDescriptorPoolSize.type"];
            internal static readonly int PoolSizeCount = BrovVulkLayout.MemberOffset["VkDescriptorPoolSize.descriptorCount"];
            internal static readonly int PoolCreateSize = BrovVulkLayout.StructSize["VkDescriptorPoolCreateInfo"];
            internal static readonly int PoolMaxSets = BrovVulkLayout.MemberOffset["VkDescriptorPoolCreateInfo.maxSets"];
            internal static readonly int PoolSizeCountMember = BrovVulkLayout.MemberOffset["VkDescriptorPoolCreateInfo.poolSizeCount"];
            internal static readonly int PoolSizes = BrovVulkLayout.MemberOffset["VkDescriptorPoolCreateInfo.pPoolSizes"];
            internal static readonly int SetAllocateSize = BrovVulkLayout.StructSize["VkDescriptorSetAllocateInfo"];
            internal static readonly int SetAllocatePool = BrovVulkLayout.MemberOffset["VkDescriptorSetAllocateInfo.descriptorPool"];
            internal static readonly int SetAllocateCount = BrovVulkLayout.MemberOffset["VkDescriptorSetAllocateInfo.descriptorSetCount"];
            internal static readonly int SetAllocateLayouts = BrovVulkLayout.MemberOffset["VkDescriptorSetAllocateInfo.pSetLayouts"];

            internal static readonly int WriteSize = BrovVulkLayout.StructSize["VkWriteDescriptorSet"];
            internal static readonly int WriteSet = BrovVulkLayout.MemberOffset["VkWriteDescriptorSet.dstSet"];
            internal static readonly int WriteBinding = BrovVulkLayout.MemberOffset["VkWriteDescriptorSet.dstBinding"];
            internal static readonly int WriteCount = BrovVulkLayout.MemberOffset["VkWriteDescriptorSet.descriptorCount"];
            internal static readonly int WriteType = BrovVulkLayout.MemberOffset["VkWriteDescriptorSet.descriptorType"];
            internal static readonly int WriteImageInfo = BrovVulkLayout.MemberOffset["VkWriteDescriptorSet.pImageInfo"];
            internal static readonly int WriteBufferInfo = BrovVulkLayout.MemberOffset["VkWriteDescriptorSet.pBufferInfo"];
            internal static readonly int ImageInfoSize = BrovVulkLayout.StructSize["VkDescriptorImageInfo"];
            internal static readonly int ImageInfoView = BrovVulkLayout.MemberOffset["VkDescriptorImageInfo.imageView"];
            internal static readonly int ImageInfoLayout = BrovVulkLayout.MemberOffset["VkDescriptorImageInfo.imageLayout"];
            internal static readonly int BufferInfoSize = BrovVulkLayout.StructSize["VkDescriptorBufferInfo"];
            internal static readonly int BufferInfoBuffer = BrovVulkLayout.MemberOffset["VkDescriptorBufferInfo.buffer"];
            internal static readonly int BufferInfoOffset = BrovVulkLayout.MemberOffset["VkDescriptorBufferInfo.offset"];
            internal static readonly int BufferInfoRange = BrovVulkLayout.MemberOffset["VkDescriptorBufferInfo.range"];

            internal static readonly int MemoryBarrierSize = BrovVulkLayout.StructSize["VkMemoryBarrier"];
            internal static readonly int MemoryBarrierSrc = BrovVulkLayout.MemberOffset["VkMemoryBarrier.srcAccessMask"];
            internal static readonly int MemoryBarrierDst = BrovVulkLayout.MemberOffset["VkMemoryBarrier.dstAccessMask"];
            internal static readonly int ImageBarrierSize = BrovVulkLayout.StructSize["VkImageMemoryBarrier"];
            internal static readonly int ImageBarrierSrc = BrovVulkLayout.MemberOffset["VkImageMemoryBarrier.srcAccessMask"];
            internal static readonly int ImageBarrierDst = BrovVulkLayout.MemberOffset["VkImageMemoryBarrier.dstAccessMask"];
            internal static readonly int ImageBarrierOld = BrovVulkLayout.MemberOffset["VkImageMemoryBarrier.oldLayout"];
            internal static readonly int ImageBarrierNew = BrovVulkLayout.MemberOffset["VkImageMemoryBarrier.newLayout"];
            internal static readonly int ImageBarrierSrcFamily = BrovVulkLayout.MemberOffset["VkImageMemoryBarrier.srcQueueFamilyIndex"];
            internal static readonly int ImageBarrierDstFamily = BrovVulkLayout.MemberOffset["VkImageMemoryBarrier.dstQueueFamilyIndex"];
            internal static readonly int ImageBarrierImage = BrovVulkLayout.MemberOffset["VkImageMemoryBarrier.image"];
            internal static readonly int ImageBarrierRange = BrovVulkLayout.MemberOffset["VkImageMemoryBarrier.subresourceRange"];

            internal static readonly int BindInfoLayout = BrovVulkLayout.MemberOffset["VkBindDescriptorSetsInfo.layout"];
            internal static readonly int BindInfoStages = BrovVulkLayout.MemberOffset["VkBindDescriptorSetsInfo.stageFlags"];
            internal static readonly int BindInfoFirst = BrovVulkLayout.MemberOffset["VkBindDescriptorSetsInfo.firstSet"];
            internal static readonly int BindInfoCount = BrovVulkLayout.MemberOffset["VkBindDescriptorSetsInfo.descriptorSetCount"];
            internal static readonly int BindInfoSets = BrovVulkLayout.MemberOffset["VkBindDescriptorSetsInfo.pDescriptorSets"];
            internal static readonly int BindInfoDynamicCount = BrovVulkLayout.MemberOffset["VkBindDescriptorSetsInfo.dynamicOffsetCount"];
            internal static readonly int BindInfoDynamicOffsets = BrovVulkLayout.MemberOffset["VkBindDescriptorSetsInfo.pDynamicOffsets"];
            internal static readonly int PushInfoLayout = BrovVulkLayout.MemberOffset["VkPushConstantsInfo.layout"];
            internal static readonly int PushInfoStages = BrovVulkLayout.MemberOffset["VkPushConstantsInfo.stageFlags"];
            internal static readonly int PushInfoOffset = BrovVulkLayout.MemberOffset["VkPushConstantsInfo.offset"];
            internal static readonly int PushInfoSize = BrovVulkLayout.MemberOffset["VkPushConstantsInfo.size"];
            internal static readonly int PushInfoValues = BrovVulkLayout.MemberOffset["VkPushConstantsInfo.pValues"];
        }

        private readonly struct RegionLayout
        {
            public readonly int Stride;
            public readonly int BufferOffset;
            public readonly int RowLength;
            public readonly int ImageHeight;
            public readonly int Subresource;
            public readonly int Offset;
            public readonly int Extent;

            public RegionLayout(string type)
            {
                Stride = BrovVulkLayout.StructSize[type];
                BufferOffset = BrovVulkLayout.MemberOffset[type + ".bufferOffset"];
                RowLength = BrovVulkLayout.MemberOffset[type + ".bufferRowLength"];
                ImageHeight = BrovVulkLayout.MemberOffset[type + ".bufferImageHeight"];
                Subresource = BrovVulkLayout.MemberOffset[type + ".imageSubresource"];
                Offset = BrovVulkLayout.MemberOffset[type + ".imageOffset"];
                Extent = BrovVulkLayout.MemberOffset[type + ".imageExtent"];
            }
        }

        private static readonly RegionLayout Region1 = new RegionLayout("VkBufferImageCopy");
        private static readonly RegionLayout Region2 = new RegionLayout("VkBufferImageCopy2");

        internal readonly struct Family
        {
            public readonly int Format;
            public readonly int[] ViewFormats;
            public readonly int WriteFormat;
            public readonly int Variant;
            public readonly uint Mode;
            public readonly int BlockBytes;

            public Family(int format, int[] viewFormats, int writeFormat, int variant, uint mode, int blockBytes)
            {
                Format = format;
                ViewFormats = viewFormats;
                WriteFormat = writeFormat;
                Variant = variant;
                Mode = mode;
                BlockBytes = blockBytes;
            }
        }

        internal sealed class ImageRecord
        {
            public IntPtr Device;
            public IntPtr Image;
            public Family Family;
            public uint Usage;
            public uint Width;
            public uint Height;
            public uint Depth;
            public bool ThreeDimensional;
            public Dictionary<ulong, IntPtr>? Views;
        }

        internal sealed class DeviceRecord
        {
            public IntPtr Device;
            public VulkanStandIns.DeviceGaps Gaps = null!;
            public IntPtr SetLayout;
            public IntPtr Layout;
            public readonly IntPtr[] Pipelines = new IntPtr[4];
            public bool Failed;
        }

        internal sealed class BindCall
        {
            public IntPtr Layout;
            public uint First;
            public IntPtr[] Sets = Array.Empty<IntPtr>();
            public uint[] Offsets = Array.Empty<uint>();
        }

        internal sealed class PushCall
        {
            public IntPtr Layout;
            public uint Stages;
            public uint Offset;
            public byte[] Data = Array.Empty<byte>();
        }

        /// <summary>What a decode leaves behind in a command buffer, and the guest state it has to put back.</summary>
        internal sealed class DecodeState
        {
            public readonly List<IntPtr> Pools = new List<IntPtr>();
            public int PoolIndex;
            public int PoolUsed;
            public IntPtr ComputePipeline;
            public readonly List<BindCall> Binds = new List<BindCall>();
            public readonly List<PushCall> Pushes = new List<PushCall>();
        }

        private static void Complain(string reason)
        {
            if (Reported.Add(reason))
                Utils.LogError("[VulkanImpls] textureCompressionBC: " + reason + ".");
        }

        internal static bool IsCompressed(int format) => format >= FormatBc1RgbUnorm && format <= FormatBc7Srgb;

        private static bool IsSrgb(int format) => format == 132 || format == 134 || format == 136 || format == 138 || format == FormatBc7Srgb;

        private static Family Describe(int format, VulkanStandIns.DeviceGaps gaps)
        {
            switch (format)
            {
                case 131:
                case 132:
                    return new Family(FormatRgba8Unorm, Rgba8Views, FormatRgba8Uint, 0, 1, 8);
                case 133:
                case 134:
                    return new Family(FormatRgba8Unorm, Rgba8Views, FormatRgba8Uint, 0, 1 | ModePunchThrough, 8);
                case 135:
                case 136:
                    return new Family(FormatRgba8Unorm, Rgba8Views, FormatRgba8Uint, 0, 2, 16);
                case 137:
                case 138:
                    return new Family(FormatRgba8Unorm, Rgba8Views, FormatRgba8Uint, 0, 3, 16);
                case FormatBc4Unorm:
                case FormatBc4Snorm:
                {
                    uint mode = 4 | (format == FormatBc4Snorm ? ModeSigned : 0);
                    int image = format == FormatBc4Snorm ? FormatR8Snorm : FormatR8Unorm;
                    return gaps.R8Storage
                        ? new Family(image, R8Views, FormatR8Uint, 2, mode, 8)
                        : new Family(format == FormatBc4Snorm ? FormatRgba8Snorm : FormatRgba8Unorm, Rgba8Views, FormatRgba8Uint, 0, mode, 8);
                }
                case FormatBc5Unorm:
                case FormatBc5Snorm:
                {
                    uint mode = 5 | (format == FormatBc5Snorm ? ModeSigned : 0);
                    int image = format == FormatBc5Snorm ? FormatRg8Snorm : FormatRg8Unorm;
                    return gaps.Rg8Storage
                        ? new Family(image, Rg8Views, FormatRg8Uint, 1, mode, 16)
                        : new Family(format == FormatBc5Snorm ? FormatRgba8Snorm : FormatRgba8Unorm, Rgba8Views, FormatRgba8Uint, 0, mode, 16);
                }
                case FormatBc6hUfloat:
                case FormatBc6hSfloat:
                    return new Family(FormatRgba16Sfloat, Rgba16Views, FormatRgba16Uint, 3, 6 | (format == FormatBc6hSfloat ? ModeSigned : 0), 16);
                default:
                    return new Family(FormatRgba8Unorm, Rgba8Views, FormatRgba8Uint, 0, 7, 16);
            }
        }

        /// <summary>The substitute a view with a BCn format gets over an image of the family, 0 when the classes differ.</summary>
        private static int ViewFormat(in Family family, int viewFormat)
        {
            int[] views = family.ViewFormats;
            bool half = viewFormat == FormatBc6hUfloat || viewFormat == FormatBc6hSfloat;
            if (views == Rgba16Views)
                return half ? FormatRgba16Sfloat : 0;
            if (half)
                return 0;

            bool snorm = viewFormat == FormatBc4Snorm || viewFormat == FormatBc5Snorm;
            if (views == R8Views)
                return viewFormat == FormatBc4Unorm || viewFormat == FormatBc4Snorm ? (snorm ? FormatR8Snorm : FormatR8Unorm) : 0;
            if (views == Rg8Views)
                return viewFormat == FormatBc5Unorm || viewFormat == FormatBc5Snorm ? (snorm ? FormatRg8Snorm : FormatRg8Unorm) : 0;
            return IsSrgb(viewFormat) ? FormatRgba8Srgb : snorm ? FormatRgba8Snorm : FormatRgba8Unorm;
        }

        private static int SampledFormat(int format, VulkanStandIns.DeviceGaps gaps)
        {
            Family family = Describe(format, gaps);
            return ViewFormat(family, format);
        }

        internal static void FormatProperties(IntPtr physicalDevice, VulkanStandIns.DeviceGaps gaps, int format, IntPtr properties)
        {
            byte* host = stackalloc byte[L.FormatPropertiesSize];
            new Span<byte>(host, L.FormatPropertiesSize).Clear();
            BrovVulkApi.vkGetPhysicalDeviceFormatProperties(physicalDevice, SampledFormat(format, gaps), (IntPtr)host);
            *(uint*)(properties + L.FormatLinear) = 0;
            *(uint*)(properties + L.FormatOptimal) = *(uint*)(host + L.FormatOptimal) & AdvertisedFeatures;
            *(uint*)(properties + L.FormatBuffer) = 0;
        }

        internal static void FormatProperties2(IntPtr physicalDevice, VulkanStandIns.DeviceGaps gaps, int format, IntPtr properties)
        {
            byte* host = stackalloc byte[L.FormatProperties2Size];
            byte* host3 = stackalloc byte[L.FormatProperties3Size];
            new Span<byte>(host, L.FormatProperties2Size).Clear();
            new Span<byte>(host3, L.FormatProperties3Size).Clear();
            *(uint*)host = StFormatProperties2;
            *(IntPtr*)(host + VkOffsets.NodePNext) = (IntPtr)host3;
            *(uint*)host3 = StFormatProperties3;
            BrovVulkApi.vkGetPhysicalDeviceFormatProperties2(physicalDevice, SampledFormat(format, gaps), (IntPtr)host);

            byte* body = (byte*)properties + L.FormatProperties2Body;
            *(uint*)(body + L.FormatLinear) = 0;
            *(uint*)(body + L.FormatOptimal) = *(uint*)(host + L.FormatProperties2Body + L.FormatOptimal) & AdvertisedFeatures;
            *(uint*)(body + L.FormatBuffer) = 0;
            for (IntPtr node = *(IntPtr*)(properties + VkOffsets.NodePNext); node != IntPtr.Zero; node = *(IntPtr*)(node + VkOffsets.NodePNext))
            {
                if (*(uint*)node != StFormatProperties3)
                    continue;

                *(ulong*)(node + L.Format3Linear) = 0;
                *(ulong*)(node + L.Format3Optimal) = *(ulong*)(host3 + L.Format3Optimal) & AdvertisedFeatures;
                *(ulong*)(node + L.Format3Buffer) = 0;
            }
        }

        private static uint SubstituteFlags(uint flags, int type)
        {
            flags &= ~ImageCreateBlockTexelViewCompatible;
            flags |= ImageCreateMutableFormat | ImageCreateExtendedUsage;
            if (type == ImageType3D)
                flags |= ImageCreate2DArrayCompatible;
            return flags;
        }

        internal static int ImageFormatProperties(VulkanStandIns.DeviceGaps gaps, ref int format, int type, int tiling, ref uint usage, ref uint flags)
        {
            if (tiling != ImageTilingOptimal)
                return ErrorFormatNotSupported;

            format = Describe(format, gaps).Format;
            flags = SubstituteFlags(flags, type);
            usage |= ImageUsageStorage;
            return 0;
        }

        internal static int ImageFormatProperties2(GenState st, VulkanStandIns.DeviceGaps gaps, IntPtr info)
        {
            if (*(int*)(info + L.ImageFormatInfoTiling) != ImageTilingOptimal)
                return ErrorFormatNotSupported;

            Family family = Describe(*(int*)(info + L.ImageFormatInfoFormat), gaps);
            *(int*)(info + L.ImageFormatInfoFormat) = family.Format;
            *(uint*)(info + L.ImageFormatInfoFlags) = SubstituteFlags(*(uint*)(info + L.ImageFormatInfoFlags), *(int*)(info + L.ImageFormatInfoType));
            *(uint*)(info + L.ImageFormatInfoUsage) |= ImageUsageStorage;
            ReplaceFormatList(st, info, family, false);
            return 0;
        }

        // The view formats a guest may name are all BCn, so the list becomes the family's own, with the write format added.
        private static void ReplaceFormatList(GenState st, IntPtr createInfo, in Family family, bool addWhenMissing)
        {
            IntPtr formats = st.Alloc(family.ViewFormats.Length * 4);
            family.ViewFormats.AsSpan().CopyTo(new Span<int>((void*)formats, family.ViewFormats.Length));

            for (IntPtr node = *(IntPtr*)(createInfo + VkOffsets.NodePNext); node != IntPtr.Zero; node = *(IntPtr*)(node + VkOffsets.NodePNext))
            {
                if (*(uint*)node != StImageFormatListCreateInfo)
                    continue;

                *(uint*)(node + L.FormatListCount) = (uint)family.ViewFormats.Length;
                *(IntPtr*)(node + L.FormatListFormats) = formats;
                return;
            }

            if (!addWhenMissing)
                return;

            IntPtr list = st.Alloc(L.FormatListSize);
            *(uint*)list = StImageFormatListCreateInfo;
            *(IntPtr*)(list + VkOffsets.NodePNext) = *(IntPtr*)(createInfo + VkOffsets.NodePNext);
            *(uint*)(list + L.FormatListCount) = (uint)family.ViewFormats.Length;
            *(IntPtr*)(list + L.FormatListFormats) = formats;
            *(IntPtr*)(createInfo + VkOffsets.NodePNext) = list;
        }

        internal static int CreateImage(GenState st, IntPtr device, IntPtr createInfo)
        {
            VulkanStandInState state = st.StandIns;
            state.PendingImage = null;
            int format = *(int*)(createInfo + L.ImageFormat);
            if (!IsCompressed(format))
                return 0;

            if (*(int*)(createInfo + L.ImageTiling) != ImageTilingOptimal)
            {
                Complain("a linear tiled BCn image was refused");
                return ErrorFormatNotSupported;
            }

            st.TryGetDevicePhysical(device, out IntPtr physicalDevice);
            VulkanStandIns.DeviceGaps gaps = VulkanStandIns.Gaps(physicalDevice);
            Family family = Describe(format, gaps);
            int type = *(int*)(createInfo + L.ImageType);
            uint usage = *(uint*)(createInfo + L.ImageUsage);
            *(int*)(createInfo + L.ImageFormat) = family.Format;
            *(uint*)(createInfo + L.ImageFlags) = SubstituteFlags(*(uint*)(createInfo + L.ImageFlags), type);
            *(uint*)(createInfo + L.ImageUsage) = usage | ImageUsageStorage;
            ReplaceFormatList(st, createInfo, family, true);

            uint* extent = (uint*)(createInfo + L.ImageExtent);
            state.PendingImage = new ImageRecord
            {
                Device = device,
                Family = family,
                Usage = usage,
                Width = extent[0],
                Height = extent[1],
                Depth = extent[2],
                ThreeDimensional = type == ImageType3D,
            };
            return 0;
        }

        internal static void NoteImage(VulkanStandInState state, IntPtr image)
        {
            ImageRecord? record = state.PendingImage;
            state.PendingImage = null;
            if (record == null || image == IntPtr.Zero)
                return;

            record.Image = image;
            state.Images[image] = record;
        }

        internal static void DestroyImage(VulkanStandInState state, IntPtr device, IntPtr image)
        {
            if (state.Images.Remove(image, out ImageRecord? record))
                DestroyViews(record);
        }

        private static void DestroyViews(ImageRecord record)
        {
            if (record.Views == null)
                return;

            foreach (IntPtr view in record.Views.Values)
                BrovVulkApi.vkDestroyImageView(record.Device, view, IntPtr.Zero);
            record.Views = null;
        }

        internal static int CreateImageView(GenState st, IntPtr createInfo)
        {
            if (!st.StandIns.Images.TryGetValue(*(IntPtr*)(createInfo + L.ViewImage), out ImageRecord? record))
                return 0;

            int format = *(int*)(createInfo + L.ViewFormat);
            int substitute = IsCompressed(format) ? ViewFormat(record.Family, format) : 0;
            if (substitute == 0)
            {
                Complain("a view that reads a BCn image as another format was refused");
                return ErrorFormatNotSupported;
            }

            *(int*)(createInfo + L.ViewFormat) = substitute;
            for (IntPtr node = *(IntPtr*)(createInfo + VkOffsets.NodePNext); node != IntPtr.Zero; node = *(IntPtr*)(node + VkOffsets.NodePNext))
            {
                if (*(uint*)node != StImageViewUsageCreateInfo)
                    continue;

                *(uint*)(node + L.ViewUsageUsage) &= ~ImageUsageStorage;
                return 0;
            }

            // The storage usage exists for the decoder's integer view only. A sampled sRGB view must not carry it.
            IntPtr usage = st.Alloc(L.ViewUsageSize);
            *(uint*)usage = StImageViewUsageCreateInfo;
            *(IntPtr*)(usage + VkOffsets.NodePNext) = *(IntPtr*)(createInfo + VkOffsets.NodePNext);
            *(uint*)(usage + L.ViewUsageUsage) = record.Usage;
            *(IntPtr*)(createInfo + VkOffsets.NodePNext) = usage;
            return 0;
        }

        internal static void CreateBuffer(IntPtr createInfo)
        {
            uint* usage = (uint*)(createInfo + L.BufferUsage);
            if ((*usage & BufferUsageTransferSrc) != 0)
                *usage |= BufferUsageStorage;

            for (IntPtr node = *(IntPtr*)(createInfo + VkOffsets.NodePNext); node != IntPtr.Zero; node = *(IntPtr*)(node + VkOffsets.NodePNext))
            {
                if (*(uint*)node != StBufferUsageFlags2CreateInfo)
                    continue;

                ulong* usage2 = (ulong*)(node + L.BufferUsage2);
                if ((*usage2 & BufferUsageTransferSrc) != 0)
                    *usage2 |= BufferUsageStorage;
            }
        }

        internal static bool RefuseReadback(VulkanStandInState state, IntPtr image)
        {
            if (!state.Images.ContainsKey(image))
                return false;

            Complain("a copy out of a BCn image was dropped, the blocks are gone once decoded");
            return true;
        }

        internal static bool RefuseMismatchedCopy(VulkanStandInState state, IntPtr source, IntPtr destination)
        {
            state.Images.TryGetValue(source, out ImageRecord? from);
            state.Images.TryGetValue(destination, out ImageRecord? to);
            if (from == null && to == null)
                return false;

            if (from != null && to != null && from.Family.Format == to.Family.Format)
                return false;

            Complain("a copy between a BCn image and an image of another format was dropped");
            return true;
        }

        internal static bool CopyBufferToImage2(GenState st, IntPtr commandBuffer, IntPtr info)
        {
            return CopyBufferToImage(st, commandBuffer, *(IntPtr*)(info + L.CopySource), *(IntPtr*)(info + L.CopyDestination),
                *(int*)(info + L.CopyLayout), *(uint*)(info + L.CopyRegionCount), *(IntPtr*)(info + L.CopyRegions), true);
        }

        internal static bool CopyBufferToImage(GenState st, IntPtr commandBuffer, IntPtr buffer, IntPtr image, int layout, uint count, IntPtr regions, bool version2)
        {
            VulkanStandInState state = st.StandIns;
            if (!state.Images.TryGetValue(image, out ImageRecord? record))
                return false;

            if (count == 0 || regions == IntPtr.Zero)
                return true;

            if (!state.CommandBuffers.TryGetValue(commandBuffer, out CommandBufferRecord? commandRecord))
            {
                Complain("a copy into a BCn image came through a command buffer this does not know");
                return true;
            }

            DeviceRecord device = Decoder(state, st, record.Device);
            if (device.Failed)
                return true;

            if (state.CommandPools.TryGetValue(commandRecord.Pool, out CommandPoolRecord? pool)
                && pool.QueueFamily < device.Gaps.QueueFamilies.Length && (device.Gaps.QueueFamilies[pool.QueueFamily] & QueueCompute) == 0)
            {
                Complain("a copy into a BCn image was recorded for a queue without compute, it was dropped");
                return true;
            }

            IntPtr pipeline = Pipeline(st, device, record.Family.Variant);
            if (pipeline == IntPtr.Zero)
                return true;

            DecodeState decode = commandRecord.Decode ??= new DecodeState();
            ref readonly RegionLayout at = ref version2 ? ref Region2 : ref Region1;
            ulong bufferSize = st.BufferSize(buffer);
            uint alignment = device.Gaps.StorageAlignment;

            IntPtr sets = AllocateSets(st, device, decode, count);
            if (sets == IntPtr.Zero)
            {
                Complain("descriptor sets for the decoder could not be allocated");
                return true;
            }

            IntPtr writes = st.Alloc(BrovVulkGenStruct.CheckedBytes(count * 2, L.WriteSize));
            IntPtr bufferInfos = st.Alloc(BrovVulkGenStruct.CheckedBytes(count, L.BufferInfoSize));
            IntPtr imageInfos = st.Alloc(BrovVulkGenStruct.CheckedBytes(count, L.ImageInfoSize));
            IntPtr before = st.Alloc(BrovVulkGenStruct.CheckedBytes(count, L.ImageBarrierSize));
            IntPtr after = st.Alloc(BrovVulkGenStruct.CheckedBytes(count, L.ImageBarrierSize));
            IntPtr pushes = st.Alloc(BrovVulkGenStruct.CheckedBytes(count, PushBytes));
            uint* groups = (uint*)st.Alloc(BrovVulkGenStruct.CheckedBytes(count, 12));

            uint prepared = 0;
            for (uint i = 0; i < count; i++)
            {
                IntPtr region = regions + (int)(i * (uint)at.Stride);
                IntPtr subresource = region + at.Subresource;
                if ((*(uint*)(subresource + L.SubresourceAspect) & ImageAspectColor) == 0)
                    continue;

                uint level = *(uint*)(subresource + L.SubresourceLevel);
                uint baseLayer = *(uint*)(subresource + L.SubresourceLayer);
                uint layerCount = *(uint*)(subresource + L.SubresourceLayers);
                int* offset = (int*)(region + at.Offset);
                uint* extent = (uint*)(region + at.Extent);
                uint width = extent[0], height = extent[1], depth = extent[2];
                if (width == 0 || height == 0 || depth == 0 || layerCount == 0)
                    continue;

                uint rowLength = *(uint*)(region + at.RowLength);
                uint imageHeight = *(uint*)(region + at.ImageHeight);
                if (rowLength == 0)
                    rowLength = width;
                if (imageHeight == 0)
                    imageHeight = height;
                uint blocksPerRow = (rowLength + 3) / 4;
                uint blocksPerSlice = blocksPerRow * ((imageHeight + 3) / 4);
                uint blocksX = (width + 3) / 4;
                uint blocksY = (height + 3) / 4;
                uint slices = record.ThreeDimensional ? depth : layerCount;

                ulong bufferOffset = *(ulong*)(region + at.BufferOffset);
                ulong bound = bufferOffset & ~((ulong)alignment - 1);
                ulong needed = bufferOffset - bound + ((ulong)(slices - 1) * blocksPerSlice + (ulong)(blocksY - 1) * blocksPerRow + blocksX) * (ulong)record.Family.BlockBytes;
                ulong range = needed;
                if (bufferSize != 0 && bound < bufferSize && bufferSize - bound < range)
                    range = bufferSize - bound;
                if (range > device.Gaps.StorageRange)
                {
                    Complain("a BCn upload is larger than the host's storage buffer range, part of it was not decoded");
                    range = device.Gaps.StorageRange;
                }

                uint viewLayer = record.ThreeDimensional ? 0 : baseLayer;
                uint viewLayers = record.ThreeDimensional ? Math.Max(1, record.Depth >> (int)level) : layerCount;
                IntPtr view = StorageView(record, level, viewLayer, viewLayers);
                if (view == IntPtr.Zero)
                {
                    Complain("a storage view of a BCn image could not be created");
                    continue;
                }

                IntPtr set = Marshal.ReadIntPtr(sets, (int)prepared * 8);
                IntPtr bufferInfo = bufferInfos + (int)(prepared * (uint)L.BufferInfoSize);
                *(IntPtr*)(bufferInfo + L.BufferInfoBuffer) = buffer;
                *(ulong*)(bufferInfo + L.BufferInfoOffset) = bound;
                *(ulong*)(bufferInfo + L.BufferInfoRange) = range;
                IntPtr imageInfo = imageInfos + (int)(prepared * (uint)L.ImageInfoSize);
                *(IntPtr*)(imageInfo + L.ImageInfoView) = view;
                *(int*)(imageInfo + L.ImageInfoLayout) = ImageLayoutGeneral;
                IntPtr write = writes + (int)(prepared * 2 * (uint)L.WriteSize);
                FillWrite(write, set, 0, DescriptorTypeStorageBuffer, IntPtr.Zero, bufferInfo);
                FillWrite(write + L.WriteSize, set, 1, DescriptorTypeStorageImage, imageInfo, IntPtr.Zero);

                uint barrierLayer = record.ThreeDimensional ? 0 : baseLayer;
                uint barrierLayers = record.ThreeDimensional ? 1 : layerCount;
                FillImageBarrier(before + (int)(prepared * (uint)L.ImageBarrierSize), image, AccessMemoryWrite, AccessShaderWrite, layout, ImageLayoutGeneral, level, barrierLayer, barrierLayers);
                FillImageBarrier(after + (int)(prepared * (uint)L.ImageBarrierSize), image, AccessShaderWrite, AccessMemoryRead | AccessMemoryWrite, ImageLayoutGeneral, layout, level, barrierLayer, barrierLayers);

                uint* push = (uint*)(pushes + (int)(prepared * PushBytes));
                push[0] = (uint)((bufferOffset - bound) / 4);
                push[1] = blocksPerRow;
                push[2] = blocksPerSlice;
                push[3] = record.Family.Mode;
                push[4] = (uint)offset[0];
                push[5] = (uint)offset[1];
                push[6] = record.ThreeDimensional ? (uint)offset[2] : 0;
                push[7] = width;
                push[8] = height;
                push[9] = slices;
                groups[prepared * 3] = (blocksX + 7) / 8;
                groups[prepared * 3 + 1] = (blocksY + 7) / 8;
                groups[prepared * 3 + 2] = slices;
                prepared++;
            }

            if (prepared == 0)
                return true;

            BrovVulkApi.vkUpdateDescriptorSets(record.Device, prepared * 2, writes, 0, IntPtr.Zero);

            IntPtr memoryBarrier = st.Alloc(L.MemoryBarrierSize);
            *(uint*)memoryBarrier = StMemoryBarrier;
            *(uint*)(memoryBarrier + L.MemoryBarrierSrc) = AccessMemoryWrite;
            *(uint*)(memoryBarrier + L.MemoryBarrierDst) = AccessShaderRead | AccessShaderWrite;
            BrovVulkApi.vkCmdPipelineBarrier(commandBuffer, PipelineStageAllCommands, PipelineStageComputeShader, 0, 1, memoryBarrier, 0, IntPtr.Zero, prepared, before);

            BrovVulkApi.vkCmdBindPipeline(commandBuffer, PipelineBindPointCompute, pipeline);
            for (uint i = 0; i < prepared; i++)
            {
                BrovVulkApi.vkCmdBindDescriptorSets(commandBuffer, PipelineBindPointCompute, device.Layout, 0, 1, sets + (int)(i * 8), 0, IntPtr.Zero);
                BrovVulkApi.vkCmdPushConstants(commandBuffer, device.Layout, ShaderStageCompute, 0, PushBytes, pushes + (int)(i * PushBytes));
                BrovVulkApi.vkCmdDispatch(commandBuffer, groups[i * 3], groups[i * 3 + 1], groups[i * 3 + 2]);
            }

            BrovVulkApi.vkCmdPipelineBarrier(commandBuffer, PipelineStageComputeShader, PipelineStageAllCommands, 0, 0, IntPtr.Zero, 0, IntPtr.Zero, prepared, after);
            Restore(st, commandBuffer, decode);
            return true;
        }

        private static void FillWrite(IntPtr write, IntPtr set, uint binding, int type, IntPtr imageInfo, IntPtr bufferInfo)
        {
            *(uint*)write = StWriteDescriptorSet;
            *(IntPtr*)(write + L.WriteSet) = set;
            *(uint*)(write + L.WriteBinding) = binding;
            *(uint*)(write + L.WriteCount) = 1;
            *(int*)(write + L.WriteType) = type;
            *(IntPtr*)(write + L.WriteImageInfo) = imageInfo;
            *(IntPtr*)(write + L.WriteBufferInfo) = bufferInfo;
        }

        private static void FillImageBarrier(IntPtr barrier, IntPtr image, uint srcAccess, uint dstAccess, int oldLayout, int newLayout, uint level, uint layer, uint layers)
        {
            *(uint*)barrier = StImageMemoryBarrier;
            *(uint*)(barrier + L.ImageBarrierSrc) = srcAccess;
            *(uint*)(barrier + L.ImageBarrierDst) = dstAccess;
            *(int*)(barrier + L.ImageBarrierOld) = oldLayout;
            *(int*)(barrier + L.ImageBarrierNew) = newLayout;
            *(uint*)(barrier + L.ImageBarrierSrcFamily) = QueueFamilyIgnored;
            *(uint*)(barrier + L.ImageBarrierDstFamily) = QueueFamilyIgnored;
            *(IntPtr*)(barrier + L.ImageBarrierImage) = image;
            uint* range = (uint*)(barrier + L.ImageBarrierRange);
            range[0] = ImageAspectColor;
            range[1] = level;
            range[2] = 1;
            range[3] = layer;
            range[4] = layers;
        }

        private static IntPtr StorageView(ImageRecord record, uint level, uint layer, uint layers)
        {
            ulong key = ((ulong)level << 48) | ((ulong)layer << 24) | layers;
            record.Views ??= new Dictionary<ulong, IntPtr>();
            if (record.Views.TryGetValue(key, out IntPtr cached))
                return cached;

            byte* usage = stackalloc byte[L.ViewUsageSize];
            new Span<byte>(usage, L.ViewUsageSize).Clear();
            *(uint*)usage = StImageViewUsageCreateInfo;
            *(uint*)(usage + L.ViewUsageUsage) = ImageUsageStorage;

            byte* info = stackalloc byte[L.ViewSize];
            new Span<byte>(info, L.ViewSize).Clear();
            *(uint*)info = StImageViewCreateInfo;
            *(IntPtr*)(info + VkOffsets.NodePNext) = (IntPtr)usage;
            *(IntPtr*)(info + L.ViewImage) = record.Image;
            *(int*)(info + L.ViewType) = ImageViewType2DArray;
            *(int*)(info + L.ViewFormat) = record.Family.WriteFormat;
            uint* range = (uint*)(info + L.ViewRange);
            range[0] = ImageAspectColor;
            range[1] = level;
            range[2] = 1;
            range[3] = layer;
            range[4] = layers;

            IntPtr view = IntPtr.Zero;
            if (BrovVulkApi.vkCreateImageView(record.Device, (IntPtr)info, IntPtr.Zero, (IntPtr)(&view)) < 0)
                return IntPtr.Zero;

            record.Views[key] = view;
            return view;
        }

        private static DeviceRecord Decoder(VulkanStandInState state, GenState st, IntPtr device)
        {
            if (state.Decoders.TryGetValue(device, out DeviceRecord? record))
                return record;

            st.TryGetDevicePhysical(device, out IntPtr physicalDevice);
            record = new DeviceRecord { Device = device, Gaps = VulkanStandIns.Gaps(physicalDevice) };
            state.Decoders[device] = record;

            IntPtr bindings = st.Alloc(2 * L.LayoutBindingSize);
            for (uint b = 0; b < 2; b++)
            {
                IntPtr binding = bindings + (int)(b * (uint)L.LayoutBindingSize);
                *(uint*)(binding + L.LayoutBindingBinding) = b;
                *(int*)(binding + L.LayoutBindingType) = b == 0 ? DescriptorTypeStorageBuffer : DescriptorTypeStorageImage;
                *(uint*)(binding + L.LayoutBindingCount) = 1;
                *(uint*)(binding + L.LayoutBindingStages) = ShaderStageCompute;
            }

            IntPtr setLayoutInfo = st.Alloc(L.SetLayoutSize);
            *(uint*)setLayoutInfo = StDescriptorSetLayoutCreateInfo;
            *(uint*)(setLayoutInfo + L.SetLayoutBindingCount) = 2;
            *(IntPtr*)(setLayoutInfo + L.SetLayoutBindings) = bindings;
            IntPtr setLayout = IntPtr.Zero;
            if (BrovVulkApi.vkCreateDescriptorSetLayout(device, setLayoutInfo, IntPtr.Zero, (IntPtr)(&setLayout)) < 0 || setLayout == IntPtr.Zero)
            {
                Fail(record, "the decoder's descriptor set layout could not be created");
                return record;
            }

            record.SetLayout = setLayout;
            IntPtr pushRange = st.Alloc(L.PushRangeSize);
            *(uint*)(pushRange + L.PushRangeStages) = ShaderStageCompute;
            *(uint*)(pushRange + L.PushRangeOffset) = 0;
            *(uint*)(pushRange + L.PushRangeSizeMember) = PushBytes;
            IntPtr layoutHandle = st.Alloc(8);
            *(IntPtr*)layoutHandle = setLayout;
            IntPtr layoutInfo = st.Alloc(L.PipelineLayoutSize);
            *(uint*)layoutInfo = StPipelineLayoutCreateInfo;
            *(uint*)(layoutInfo + L.PipelineLayoutSetCount) = 1;
            *(IntPtr*)(layoutInfo + L.PipelineLayoutSets) = layoutHandle;
            *(uint*)(layoutInfo + L.PipelineLayoutPushCount) = 1;
            *(IntPtr*)(layoutInfo + L.PipelineLayoutPushRanges) = pushRange;
            IntPtr layout = IntPtr.Zero;
            if (BrovVulkApi.vkCreatePipelineLayout(device, layoutInfo, IntPtr.Zero, (IntPtr)(&layout)) < 0 || layout == IntPtr.Zero)
            {
                Fail(record, "the decoder's pipeline layout could not be created");
                return record;
            }

            record.Layout = layout;
            return record;
        }

        private static void Fail(DeviceRecord record, string reason)
        {
            record.Failed = true;
            Complain(reason + ", BCn images stay undecoded");
        }

        private static byte[]? Code(int variant)
        {
            byte[]? code = VariantCode[variant];
            if (code != null)
                return code;

            using Stream? stream = typeof(TextureCompressionBC).Assembly.GetManifestResourceStream(ResourcePrefix + VariantNames[variant] + ".spv");
            if (stream == null)
                return null;

            code = new byte[stream.Length];
            int read = 0;
            while (read < code.Length)
            {
                int n = stream.Read(code, read, code.Length - read);
                if (n <= 0)
                    return null;
                read += n;
            }

            VariantCode[variant] = code;
            return code;
        }

        private static IntPtr Pipeline(GenState st, DeviceRecord device, int variant)
        {
            IntPtr pipeline = device.Pipelines[variant];
            if (pipeline != IntPtr.Zero)
                return pipeline;

            byte[]? code = Code(variant);
            if (code == null)
            {
                Fail(device, "the decoder shader " + VariantNames[variant] + " is missing from the build");
                return IntPtr.Zero;
            }

            IntPtr words = st.Alloc(code.Length);
            code.AsSpan().CopyTo(new Span<byte>((void*)words, code.Length));
            IntPtr moduleInfo = st.Alloc(VkOffsets.ShaderModuleSize);
            *(uint*)moduleInfo = StShaderModuleCreateInfo;
            *(ulong*)(moduleInfo + VkOffsets.ShaderModuleCodeSize) = (ulong)code.Length;
            *(IntPtr*)(moduleInfo + VkOffsets.ShaderModuleCode) = words;
            IntPtr module = IntPtr.Zero;
            if (BrovVulkApi.vkCreateShaderModule(device.Device, moduleInfo, IntPtr.Zero, (IntPtr)(&module)) < 0 || module == IntPtr.Zero)
            {
                Fail(device, "the decoder shader " + VariantNames[variant] + " was refused by the driver");
                return IntPtr.Zero;
            }

            IntPtr name = st.Alloc(8);
            *(uint*)name = 0x6E69616Du;
            IntPtr info = st.Alloc(L.ComputePipelineSize);
            *(uint*)info = StComputePipelineCreateInfo;
            IntPtr stage = info + L.ComputePipelineStage;
            *(uint*)stage = StPipelineShaderStageCreateInfo;
            *(uint*)(stage + VkOffsets.StageStage) = ShaderStageCompute;
            *(IntPtr*)(stage + VkOffsets.StageModule) = module;
            *(IntPtr*)(stage + VkOffsets.StageName) = name;
            *(IntPtr*)(info + L.ComputePipelineLayout) = device.Layout;
            *(int*)(info + L.ComputePipelineBaseIndex) = -1;
            int result = (int)BrovVulkApi.vkCreateComputePipelines(device.Device, IntPtr.Zero, 1, info, IntPtr.Zero, (IntPtr)(&pipeline));
            BrovVulkApi.vkDestroyShaderModule(device.Device, module, IntPtr.Zero);
            if (result < 0 || pipeline == IntPtr.Zero)
            {
                Fail(device, "the decoder pipeline " + VariantNames[variant] + " could not be created");
                return IntPtr.Zero;
            }

            device.Pipelines[variant] = pipeline;
            return pipeline;
        }

        private static IntPtr AllocateSets(GenState st, DeviceRecord device, DecodeState decode, uint count)
        {
            IntPtr sets = st.Alloc(BrovVulkGenStruct.CheckedBytes(count, 8));
            IntPtr layouts = st.Alloc(BrovVulkGenStruct.CheckedBytes(Math.Min(count, PoolSets), 8));
            for (uint k = 0; k < Math.Min(count, PoolSets); k++)
                *(IntPtr*)(layouts + (int)(k * 8)) = device.SetLayout;

            IntPtr info = st.Alloc(L.SetAllocateSize);
            *(uint*)info = StDescriptorSetAllocateInfo;
            *(IntPtr*)(info + L.SetAllocateLayouts) = layouts;

            uint done = 0;
            while (done < count)
            {
                if (decode.PoolIndex >= decode.Pools.Count)
                {
                    IntPtr pool = CreatePool(st, device.Device);
                    if (pool == IntPtr.Zero)
                        return IntPtr.Zero;
                    decode.Pools.Add(pool);
                    decode.PoolUsed = 0;
                }

                uint take = Math.Min(count - done, (uint)(PoolSets - decode.PoolUsed));
                if (take == 0)
                {
                    decode.PoolIndex++;
                    decode.PoolUsed = 0;
                    continue;
                }

                *(IntPtr*)(info + L.SetAllocatePool) = decode.Pools[decode.PoolIndex];
                *(uint*)(info + L.SetAllocateCount) = take;
                if (BrovVulkApi.vkAllocateDescriptorSets(device.Device, info, sets + (int)(done * 8)) < 0)
                    return IntPtr.Zero;

                decode.PoolUsed += (int)take;
                done += take;
            }

            return sets;
        }

        private static IntPtr CreatePool(GenState st, IntPtr device)
        {
            IntPtr sizes = st.Alloc(2 * L.PoolSizeSize);
            *(int*)(sizes + L.PoolSizeType) = DescriptorTypeStorageBuffer;
            *(uint*)(sizes + L.PoolSizeCount) = PoolSets;
            *(int*)(sizes + L.PoolSizeSize + L.PoolSizeType) = DescriptorTypeStorageImage;
            *(uint*)(sizes + L.PoolSizeSize + L.PoolSizeCount) = PoolSets;
            IntPtr info = st.Alloc(L.PoolCreateSize);
            *(uint*)info = StDescriptorPoolCreateInfo;
            *(uint*)(info + L.PoolMaxSets) = PoolSets;
            *(uint*)(info + L.PoolSizeCountMember) = 2;
            *(IntPtr*)(info + L.PoolSizes) = sizes;
            IntPtr pool = IntPtr.Zero;
            if (BrovVulkApi.vkCreateDescriptorPool(device, info, IntPtr.Zero, (IntPtr)(&pool)) < 0)
                return IntPtr.Zero;
            return pool;
        }

        private static void Restore(GenState st, IntPtr commandBuffer, DecodeState decode)
        {
            if (decode.ComputePipeline != IntPtr.Zero)
                BrovVulkApi.vkCmdBindPipeline(commandBuffer, PipelineBindPointCompute, decode.ComputePipeline);

            foreach (BindCall bind in decode.Binds)
            {
                IntPtr sets = st.Alloc(bind.Sets.Length * 8);
                bind.Sets.AsSpan().CopyTo(new Span<IntPtr>((void*)sets, bind.Sets.Length));
                IntPtr offsets = IntPtr.Zero;
                if (bind.Offsets.Length != 0)
                {
                    offsets = st.Alloc(bind.Offsets.Length * 4);
                    bind.Offsets.AsSpan().CopyTo(new Span<uint>((void*)offsets, bind.Offsets.Length));
                }

                BrovVulkApi.vkCmdBindDescriptorSets(commandBuffer, PipelineBindPointCompute, bind.Layout, bind.First, (uint)bind.Sets.Length, sets, (uint)bind.Offsets.Length, offsets);
            }

            foreach (PushCall push in decode.Pushes)
            {
                IntPtr data = st.Alloc(push.Data.Length);
                push.Data.AsSpan().CopyTo(new Span<byte>((void*)data, push.Data.Length));
                BrovVulkApi.vkCmdPushConstants(commandBuffer, push.Layout, push.Stages, push.Offset, (uint)push.Data.Length, data);
            }
        }

        internal static void NoteComputePipeline(CommandBufferRecord record, IntPtr pipeline)
        {
            (record.Decode ??= new DecodeState()).ComputePipeline = pipeline;
        }

        internal static void NoteDescriptorSets(CommandBufferRecord record, IntPtr layout, uint firstSet, uint count, IntPtr sets, uint dynamicCount, IntPtr dynamicOffsets)
        {
            if (count == 0 || sets == IntPtr.Zero)
                return;

            DecodeState decode = record.Decode ??= new DecodeState();
            BindCall call = new BindCall { Layout = layout, First = firstSet, Sets = new IntPtr[count] };
            new ReadOnlySpan<IntPtr>((void*)sets, (int)count).CopyTo(call.Sets);
            if (dynamicCount != 0 && dynamicOffsets != IntPtr.Zero)
            {
                call.Offsets = new uint[dynamicCount];
                new ReadOnlySpan<uint>((void*)dynamicOffsets, (int)dynamicCount).CopyTo(call.Offsets);
            }

            for (int k = 0; k < decode.Binds.Count; k++)
            {
                BindCall previous = decode.Binds[k];
                if (previous.First >= firstSet && previous.First + previous.Sets.Length <= firstSet + count)
                    decode.Binds.RemoveAt(k--);
            }

            if (decode.Binds.Count >= MaxReplayCalls)
                decode.Binds.RemoveAt(0);
            decode.Binds.Add(call);
        }

        internal static void NoteDescriptorSets2(CommandBufferRecord record, IntPtr info)
        {
            if ((*(uint*)(info + L.BindInfoStages) & ShaderStageCompute) == 0)
                return;

            NoteDescriptorSets(record, *(IntPtr*)(info + L.BindInfoLayout), *(uint*)(info + L.BindInfoFirst), *(uint*)(info + L.BindInfoCount),
                *(IntPtr*)(info + L.BindInfoSets), *(uint*)(info + L.BindInfoDynamicCount), *(IntPtr*)(info + L.BindInfoDynamicOffsets));
        }

        internal static void NotePushConstants(CommandBufferRecord record, IntPtr layout, uint stages, uint offset, uint size, IntPtr values)
        {
            if (size == 0 || values == IntPtr.Zero || offset + size > MaxPushBytes)
                return;

            DecodeState decode = record.Decode ??= new DecodeState();
            PushCall call = new PushCall { Layout = layout, Stages = stages, Offset = offset, Data = new byte[size] };
            new ReadOnlySpan<byte>((void*)values, (int)size).CopyTo(call.Data);
            for (int k = 0; k < decode.Pushes.Count; k++)
            {
                PushCall previous = decode.Pushes[k];
                if (previous.Offset >= offset && previous.Offset + previous.Data.Length <= offset + size)
                    decode.Pushes.RemoveAt(k--);
            }

            if (decode.Pushes.Count >= MaxReplayCalls)
                decode.Pushes.RemoveAt(0);
            decode.Pushes.Add(call);
        }

        internal static void NotePushConstants2(CommandBufferRecord record, IntPtr info)
        {
            NotePushConstants(record, *(IntPtr*)(info + L.PushInfoLayout), *(uint*)(info + L.PushInfoStages), *(uint*)(info + L.PushInfoOffset),
                *(uint*)(info + L.PushInfoSize), *(IntPtr*)(info + L.PushInfoValues));
        }

        internal static void ResetCommandBuffer(CommandBufferRecord record)
        {
            DecodeState? decode = record.Decode;
            if (decode == null)
                return;

            foreach (IntPtr pool in decode.Pools)
                BrovVulkApi.vkResetDescriptorPool(record.Device, pool, 0);
            decode.PoolIndex = 0;
            decode.PoolUsed = 0;
            decode.ComputePipeline = IntPtr.Zero;
            decode.Binds.Clear();
            decode.Pushes.Clear();
        }

        internal static void ReleaseCommandBuffer(CommandBufferRecord record)
        {
            DecodeState? decode = record.Decode;
            if (decode == null)
                return;

            foreach (IntPtr pool in decode.Pools)
                BrovVulkApi.vkDestroyDescriptorPool(record.Device, pool, IntPtr.Zero);
            record.Decode = null;
        }

        internal static void ReleaseDevice(VulkanStandInState state, IntPtr device)
        {
            List<IntPtr> gone = new List<IntPtr>();
            foreach (KeyValuePair<IntPtr, ImageRecord> entry in state.Images)
            {
                if (device != IntPtr.Zero && entry.Value.Device != device)
                    continue;

                DestroyViews(entry.Value);
                gone.Add(entry.Key);
            }

            foreach (IntPtr key in gone)
                state.Images.Remove(key);

            gone.Clear();
            foreach (KeyValuePair<IntPtr, DeviceRecord> entry in state.Decoders)
            {
                if (device != IntPtr.Zero && entry.Key != device)
                    continue;

                DeviceRecord record = entry.Value;
                foreach (IntPtr pipeline in record.Pipelines)
                {
                    if (pipeline != IntPtr.Zero)
                        BrovVulkApi.vkDestroyPipeline(record.Device, pipeline, IntPtr.Zero);
                }

                if (record.Layout != IntPtr.Zero)
                    BrovVulkApi.vkDestroyPipelineLayout(record.Device, record.Layout, IntPtr.Zero);
                if (record.SetLayout != IntPtr.Zero)
                    BrovVulkApi.vkDestroyDescriptorSetLayout(record.Device, record.SetLayout, IntPtr.Zero);
                gone.Add(entry.Key);
            }

            foreach (IntPtr key in gone)
                state.Decoders.Remove(key);
        }
    }
}
