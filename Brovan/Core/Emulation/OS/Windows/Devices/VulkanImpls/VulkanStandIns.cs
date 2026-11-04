using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// Core Vulkan features presented to the guest when the host driver lacks them. Probes the host, patches
    /// the feature queries and routes the hooks the generated dispatch calls. One file per stand-in.
    /// </summary>
    internal static unsafe class VulkanStandIns
    {
        internal const int MultiViewportBit = 1 << 0;
        internal const int FillModeNonSolidBit = 1 << 1;
        internal const int TextureCompressionBcBit = 1 << 2;
        internal const int ClipDistanceBit = 1 << 3;
        internal const int CullDistanceBit = 1 << 4;
        internal const int OcclusionQueryPreciseBit = 1 << 5;
        internal const int MultiDrawIndirectBit = 1 << 6;
        internal const int SamplerAnisotropyBit = 1 << 7;

        internal const int HostGeometryShaderBit = 1 << 8;
        internal const int HostGeometryPointSizeBit = 1 << 9;
        internal const int HostClipDistanceBit = 1 << 10;
        internal const int HostCullDistanceBit = 1 << 11;
        internal const int HostDepthClampBit = 1 << 12;

        internal const int HostCpuDeviceBit = 1 << 13;

        internal const int Maintenance5Bit = 1 << 16;
        internal const int Maintenance6Bit = 1 << 17;
        internal const int LoadStoreOpNoneBit = 1 << 18;
        internal const int DepthClipEnableBit = 1 << 19;
        internal const int PipelineLibraryBit = 1 << 20;
        internal const int RobustBufferAccess2Bit = 1 << 21;

        private const int RelocationBits = MultiViewportBit | ClipDistanceBit | CullDistanceBit;
        private const int PipelineBits = RelocationBits | FillModeNonSolidBit | Maintenance5Bit | DepthClipEnableBit;

        private const string FeaturePrefix = "VkPhysicalDeviceFeatures.";

        private const string ForceVariable = "BROVVULK_FORCE_STANDINS";
        private const string CpuDeviceName = "cpuDevice";

        private const uint StPhysicalDeviceFeatures2 = 1000059000u;
        private const uint ApiVersion11 = (1u << 22) | (1u << 12);
        private const uint ApiVersion12 = (1u << 22) | (2u << 12);
        private const uint StPhysicalDeviceVulkan12Features = 51u;
        private const uint StPhysicalDeviceVulkan13Features = (uint)BrovVulkConstants.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_VULKAN_1_3_FEATURES;
        private const uint StPhysicalDeviceDescriptorIndexingFeatures = (uint)BrovVulkConstants.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_DESCRIPTOR_INDEXING_FEATURES;
        private const uint StPhysicalDeviceInlineUniformBlockFeatures = (uint)BrovVulkConstants.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_INLINE_UNIFORM_BLOCK_FEATURES;
        private const uint StPhysicalDeviceVulkan14Features = 55u;
        private const uint StPhysicalDeviceTransformFeedbackFeaturesExt = 1000028000u;
        private const uint StPhysicalDeviceRobustness2FeaturesExt = 1000286000u;
        private const uint StPhysicalDeviceBufferDeviceAddressFeatures = (uint)BrovVulkConstants.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_BUFFER_DEVICE_ADDRESS_FEATURES;
        private const uint StPhysicalDeviceTimelineSemaphoreFeatures = (uint)BrovVulkConstants.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TIMELINE_SEMAPHORE_FEATURES;
        private const uint StPhysicalDeviceDepthClipEnableFeaturesExt = 1000102000u;
        private const uint StPhysicalDeviceMaintenance5Features = 1000470000u;
        private const uint StPhysicalDeviceMaintenance5Properties = 1000470001u;
        private const uint StPhysicalDeviceMaintenance6Features = 1000545000u;
        private const uint StPhysicalDeviceMaintenance6Properties = 1000545001u;

        private const string LoadStoreOpNoneKhr = "VK_KHR_load_store_op_none";
        private const string LoadStoreOpNoneExt = "VK_EXT_load_store_op_none";
        private const string RobustBufferAccess2Name = "robustBufferAccess2";

        private const int PipelineBindPointCompute = 1;
        private const uint QueryControlPrecise = 1;
        private const uint QueueGraphics = 1;
        private const uint QueueCompute = 2;
        private const uint QueueTransfer = 4;
        private const int MaxLocations = 32;
        private const int ErrorFormatNotSupported = -11;
        private const int PolygonModeFill = 0;

        // SAMPLED_IMAGE | TRANSFER_DST, all a transcode target has to answer for.
        private const uint TranscodeFeatures = 0x1 | 0x4000;

        // One guest multi draw becomes this many host draws at most, and the limit is reported to match.
        internal const uint MaxStandInDrawCount = 1024;

        internal const int IndirectKindDraw = 0;
        internal const int IndirectKindIndexed = 1;
        internal const int IndirectKindMeshExt = 2;
        internal const int IndirectKindMeshNv = 3;

        private static readonly int DeviceCreateInfoPNext = BrovVulkLayout.MemberOffset["VkDeviceCreateInfo.pNext"];
        private static readonly int DeviceCreateInfoEnabledFeatures = BrovVulkLayout.MemberOffset["VkDeviceCreateInfo.pEnabledFeatures"];
        internal static readonly int DeviceCreateInfoExtensionCount = BrovVulkLayout.MemberOffset["VkDeviceCreateInfo.enabledExtensionCount"];
        internal static readonly int DeviceCreateInfoExtensionNames = BrovVulkLayout.MemberOffset["VkDeviceCreateInfo.ppEnabledExtensionNames"];

        // Every feature struct shares the VkPhysicalDeviceFeatures2 header.
        private static readonly int FeatureBits = BrovVulkLayout.MemberOffset["VkPhysicalDeviceFeatures2.features"];
        private static readonly int Vulkan12DrawIndirectCount = BrovVulkLayout.MemberOffset["VkPhysicalDeviceVulkan12Features.drawIndirectCount"];
        private static readonly int Vulkan14Maintenance5 = BrovVulkLayout.MemberOffset["VkPhysicalDeviceVulkan14Features.maintenance5"];
        private static readonly int Vulkan14Maintenance6 = BrovVulkLayout.MemberOffset["VkPhysicalDeviceVulkan14Features.maintenance6"];
        private static readonly int Robustness2BufferAccess2 = BrovVulkLayout.MemberOffset["VkPhysicalDeviceRobustness2FeaturesKHR.robustBufferAccess2"];
        private static readonly int DepthClipEnableFeature = BrovVulkLayout.MemberOffset["VkPhysicalDeviceDepthClipEnableFeaturesEXT.depthClipEnable"];
        private static readonly int Maintenance5Feature = BrovVulkLayout.MemberOffset["VkPhysicalDeviceMaintenance5Features.maintenance5"];
        private static readonly int Maintenance6Feature = BrovVulkLayout.MemberOffset["VkPhysicalDeviceMaintenance6Features.maintenance6"];
        private static readonly int Maintenance5PropertiesSize = BrovVulkLayout.StructSize["VkPhysicalDeviceMaintenance5Properties"];

        private static readonly int Vulkan12CaptureReplay = BrovVulkLayout.MemberOffset["VkPhysicalDeviceVulkan12Features.bufferDeviceAddressCaptureReplay"];
        private static readonly int Vulkan12MultiDevice = BrovVulkLayout.MemberOffset["VkPhysicalDeviceVulkan12Features.bufferDeviceAddressMultiDevice"];
        private static readonly int AddressCaptureReplay = BrovVulkLayout.MemberOffset["VkPhysicalDeviceBufferDeviceAddressFeatures.bufferDeviceAddressCaptureReplay"];
        private static readonly int AddressMultiDevice = BrovVulkLayout.MemberOffset["VkPhysicalDeviceBufferDeviceAddressFeatures.bufferDeviceAddressMultiDevice"];
        private static readonly int Robustness2ImageAccess2 = BrovVulkLayout.MemberOffset["VkPhysicalDeviceRobustness2FeaturesKHR.robustImageAccess2"];
        private static readonly int Robustness2NullDescriptor = BrovVulkLayout.MemberOffset["VkPhysicalDeviceRobustness2FeaturesKHR.nullDescriptor"];
        private static readonly int Robustness2Size = BrovVulkLayout.StructSize["VkPhysicalDeviceRobustness2FeaturesKHR"];
        private static readonly int Vulkan12Timeline = BrovVulkLayout.MemberOffset["VkPhysicalDeviceVulkan12Features.timelineSemaphore"];
        private static readonly int TimelineFeature = BrovVulkLayout.MemberOffset["VkPhysicalDeviceTimelineSemaphoreFeatures.timelineSemaphore"];
        private static readonly int TimelineFeaturesSize = BrovVulkLayout.StructSize["VkPhysicalDeviceTimelineSemaphoreFeatures"];

        // Sparse binds can change backing without a retirement event.
        private static readonly string[] SparseFeatures =
        {
            "sparseBinding", "sparseResidencyBuffer", "sparseResidencyImage2D", "sparseResidencyImage3D", "sparseResidency2Samples",
            "sparseResidency4Samples", "sparseResidency8Samples", "sparseResidency16Samples", "sparseResidencyAliased",
        };

        // A torn buffer or storage descriptor can point outside its resource.
        private static readonly string[] UpdateAfterBindFeatures =
        {
            "descriptorBindingUniformBufferUpdateAfterBind", "descriptorBindingStorageImageUpdateAfterBind", "descriptorBindingStorageBufferUpdateAfterBind",
            "descriptorBindingUniformTexelBufferUpdateAfterBind", "descriptorBindingStorageTexelBufferUpdateAfterBind",
        };

        private static readonly int[] Vulkan12UpdateAfterBind = UpdateAfterBindOffsets("VkPhysicalDeviceVulkan12Features");
        private static readonly int[] IndexingUpdateAfterBind = UpdateAfterBindOffsets("VkPhysicalDeviceDescriptorIndexingFeatures");
        private static readonly int Vulkan13InlineUpdateAfterBind = BrovVulkLayout.MemberOffset["VkPhysicalDeviceVulkan13Features.descriptorBindingInlineUniformBlockUpdateAfterBind"];
        private static readonly int InlineBlockUpdateAfterBind = BrovVulkLayout.MemberOffset["VkPhysicalDeviceInlineUniformBlockFeatures.descriptorBindingInlineUniformBlockUpdateAfterBind"];

        private static int[] UpdateAfterBindOffsets(string type) =>
            Array.ConvertAll(UpdateAfterBindFeatures, feature => BrovVulkLayout.MemberOffset[type + "." + feature]);

        private static void ClearCpuWithheld(IntPtr node)
        {
            switch (*(uint*)node)
            {
                case StPhysicalDeviceVulkan12Features:
                    *(uint*)(node + Vulkan12CaptureReplay) = *(uint*)(node + Vulkan12MultiDevice) = 0;
                    foreach (int offset in Vulkan12UpdateAfterBind)
                        *(uint*)(node + offset) = 0;
                    break;
                case StPhysicalDeviceDescriptorIndexingFeatures:
                    foreach (int offset in IndexingUpdateAfterBind)
                        *(uint*)(node + offset) = 0;
                    break;
                case StPhysicalDeviceVulkan13Features:
                    *(uint*)(node + Vulkan13InlineUpdateAfterBind) = 0;
                    break;
                case StPhysicalDeviceInlineUniformBlockFeatures:
                    *(uint*)(node + InlineBlockUpdateAfterBind) = 0;
                    break;
                case StPhysicalDeviceBufferDeviceAddressFeatures:
                    *(uint*)(node + AddressCaptureReplay) = *(uint*)(node + AddressMultiDevice) = 0;
                    break;
            }
        }

        private static readonly int Properties2Properties = BrovVulkLayout.MemberOffset["VkPhysicalDeviceProperties2.properties"];
        private static readonly int PropertiesDeviceType = BrovVulkLayout.MemberOffset["VkPhysicalDeviceProperties.deviceType"];
        private static readonly int PropertiesLimits = BrovVulkLayout.MemberOffset["VkPhysicalDeviceProperties.limits"];
        private static readonly int LimitsDrawIndirectCount = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.maxDrawIndirectCount"];
        private static readonly int LimitsSamplerAnisotropy = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.maxSamplerAnisotropy"];
        private static readonly int SamplerAnisotropyEnable = BrovVulkLayout.MemberOffset["VkSamplerCreateInfo.anisotropyEnable"];
        private static readonly int SamplerMaxAnisotropy = BrovVulkLayout.MemberOffset["VkSamplerCreateInfo.maxAnisotropy"];
        private static readonly int LimitsStorageAlignment = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.minStorageBufferOffsetAlignment"];
        private static readonly int LimitsStorageRange = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.maxStorageBufferRange"];
        private static readonly int LimitsImageDimension1D = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.maxImageDimension1D"];
        private static readonly int LimitsImageDimension2D = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.maxImageDimension2D"];
        private static readonly int LimitsImageDimension3D = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.maxImageDimension3D"];
        private static readonly int LimitsImageDimensionCube = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.maxImageDimensionCube"];
        private static readonly int LimitsColorAttachments = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.maxColorAttachments"];
        private static readonly int LimitsUniformBuffersDynamic = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.maxDescriptorSetUniformBuffersDynamic"];
        private static readonly int LimitsStorageBuffersDynamic = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.maxDescriptorSetStorageBuffersDynamic"];
        private static readonly int LimitsPushConstantsSize = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.maxPushConstantsSize"];
        private static readonly int LimitsBoundDescriptorSets = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.maxBoundDescriptorSets"];
        private static readonly int LimitsViewports = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.maxViewports"];
        private static readonly int LimitsVertexInputBindings = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.maxVertexInputBindings"];
        private static readonly int LimitsVertexInputAttributes = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.maxVertexInputAttributes"];

        private static void ProbeExtensionLimits(IntPtr physicalDevice, DeviceGaps gaps)
        {
            if (gaps.ApiVersion < ApiVersion11)
                return;

            int size = BrovVulkLayout.StructSize["VkPhysicalDeviceProperties2"];
            int pushSize = BrovVulkLayout.StructSize["VkPhysicalDevicePushDescriptorProperties"];
            int inlineSize = BrovVulkLayout.StructSize["VkPhysicalDeviceInlineUniformBlockProperties"];
            int feedbackSize = BrovVulkLayout.StructSize["VkPhysicalDeviceTransformFeedbackPropertiesEXT"];
            byte* properties = stackalloc byte[size];
            byte* push = stackalloc byte[pushSize];
            byte* inlineBlocks = stackalloc byte[inlineSize];
            byte* feedback = stackalloc byte[feedbackSize];
            new Span<byte>(properties, size).Clear();
            new Span<byte>(push, pushSize).Clear();
            new Span<byte>(inlineBlocks, inlineSize).Clear();
            new Span<byte>(feedback, feedbackSize).Clear();
            *(int*)properties = BrovVulkConstants.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PROPERTIES_2;
            *(IntPtr*)(properties + VkOffsets.NodePNext) = (IntPtr)push;
            *(int*)push = BrovVulkConstants.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_PUSH_DESCRIPTOR_PROPERTIES;
            *(IntPtr*)(push + VkOffsets.NodePNext) = (IntPtr)inlineBlocks;
            *(int*)inlineBlocks = BrovVulkConstants.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_INLINE_UNIFORM_BLOCK_PROPERTIES;
            *(IntPtr*)(inlineBlocks + VkOffsets.NodePNext) = (IntPtr)feedback;
            *(int*)feedback = BrovVulkConstants.VK_STRUCTURE_TYPE_PHYSICAL_DEVICE_TRANSFORM_FEEDBACK_PROPERTIES_EXT;
            BrovVulkApi.vkGetPhysicalDeviceProperties2(physicalDevice, (IntPtr)properties);
            gaps.MaxPushDescriptors = *(uint*)(push + BrovVulkLayout.MemberOffset["VkPhysicalDevicePushDescriptorProperties.maxPushDescriptors"]);
            gaps.MaxInlineUniformBlockSize = *(uint*)(inlineBlocks + BrovVulkLayout.MemberOffset["VkPhysicalDeviceInlineUniformBlockProperties.maxInlineUniformBlockSize"]);
            gaps.MaxTransformFeedbackBuffers = *(uint*)(feedback + BrovVulkLayout.MemberOffset["VkPhysicalDeviceTransformFeedbackPropertiesEXT.maxTransformFeedbackBuffers"]);
        }
        private static readonly int ImageFormatPropertiesSize = BrovVulkLayout.StructSize["VkImageFormatProperties"];
        private static readonly int ImageFormatMaxWidth = BrovVulkLayout.MemberOffset["VkImageFormatProperties.maxExtent"] + BrovVulkLayout.MemberOffset["VkExtent3D.width"];
        private static readonly int ImageFormatMaxHeight = BrovVulkLayout.MemberOffset["VkImageFormatProperties.maxExtent"] + BrovVulkLayout.MemberOffset["VkExtent3D.height"];
        private static readonly int ImageFormatMaxDepth = BrovVulkLayout.MemberOffset["VkImageFormatProperties.maxExtent"] + BrovVulkLayout.MemberOffset["VkExtent3D.depth"];
        private static readonly int ImageFormatMaxMipLevels = BrovVulkLayout.MemberOffset["VkImageFormatProperties.maxMipLevels"];
        private static readonly int LimitsVertexOutputs = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.maxVertexOutputComponents"];
        private static readonly int LimitsGeometryOutputs = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.maxGeometryOutputComponents"];
        private static readonly int LimitsTessellationOutputs = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.maxTessellationEvaluationOutputComponents"];
        private static readonly int LimitsFragmentInputs = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.maxFragmentInputComponents"];
        private static readonly int QueueFamilyFlags = BrovVulkLayout.MemberOffset["VkQueueFamilyProperties.queueFlags"];
        private static readonly int QueueFamilySize = BrovVulkLayout.StructSize["VkQueueFamilyProperties"];
        private static readonly int FormatPropertiesSize = BrovVulkLayout.StructSize["VkFormatProperties"];
        private static readonly int FormatPropertiesOptimal = BrovVulkLayout.MemberOffset["VkFormatProperties.optimalTilingFeatures"];
        private static readonly int CommandPoolQueueFamily = BrovVulkLayout.MemberOffset["VkCommandPoolCreateInfo.queueFamilyIndex"];
        private static readonly int CommandBufferAllocatePool = BrovVulkLayout.MemberOffset["VkCommandBufferAllocateInfo.commandPool"];

        private static readonly (int Bit, string Name)[] Features =
        {
            (MultiViewportBit, "multiViewport"),
            (FillModeNonSolidBit, "fillModeNonSolid"),
            (TextureCompressionBcBit, "textureCompressionBC"),
            (ClipDistanceBit, "shaderClipDistance"),
            (CullDistanceBit, "shaderCullDistance"),
            (OcclusionQueryPreciseBit, "occlusionQueryPrecise"),
            (MultiDrawIndirectBit, "multiDrawIndirect"),
            (SamplerAnisotropyBit, "samplerAnisotropy"),
        };

        private static readonly (int Bit, string Name)[] HostAbilities =
        {
            (HostGeometryShaderBit, "geometryShader"),
            (HostGeometryPointSizeBit, "shaderTessellationAndGeometryPointSize"),
            (HostClipDistanceBit, "shaderClipDistance"),
            (HostCullDistanceBit, "shaderCullDistance"),
            (HostDepthClampBit, "depthClamp"),
        };

        // Translates is false when the guest only needs the name, so forcing the entry has nothing to exercise.
        private static readonly (int Bit, string Name, bool Translates)[] Extensions =
        {
            (Maintenance5Bit, "VK_KHR_maintenance5", true),
            (Maintenance6Bit, "VK_KHR_maintenance6", true),
            (LoadStoreOpNoneBit, LoadStoreOpNoneKhr, true),
            (DepthClipEnableBit, "VK_EXT_depth_clip_enable", true),
            (PipelineLibraryBit, "VK_KHR_pipeline_library", false),
        };

        private static readonly IntPtr LoadStoreOpNoneKhrName = Marshal.StringToHGlobalAnsi(LoadStoreOpNoneKhr);
        private static readonly IntPtr LoadStoreOpNoneExtName = Marshal.StringToHGlobalAnsi(LoadStoreOpNoneExt);
        private static readonly IntPtr Robustness2KhrName = Marshal.StringToHGlobalAnsi("VK_KHR_robustness2");
        private static readonly IntPtr Robustness2ExtName = Marshal.StringToHGlobalAnsi("VK_EXT_robustness2");
        private static readonly IntPtr TimelineSemaphoreName = Marshal.StringToHGlobalAnsi("VK_KHR_timeline_semaphore");

        private static readonly string[] CoreFeatures = BuildCoreFeatures();
        private static readonly string[] Forced = ReadForced();

        private static readonly object Lock = new object();
        private static readonly Dictionary<IntPtr, DeviceGaps> GapsByDevice = new Dictionary<IntPtr, DeviceGaps>();

        /// <summary>True once a device with a stand-in exists. The hooks return at once while it is false.</summary>
        internal static bool Any;

        /// <summary>Advertise the missing features that have no stand-in.</summary>
        internal static bool Relax;

        internal sealed class DeviceGaps
        {
            public int ImplementedBits;
            public int HostBits;
            public uint ApiVersion;
            public string[] Missing = Array.Empty<string>();
            public Dictionary<string, uint> HostExtensions = new Dictionary<string, uint>(StringComparer.Ordinal);
            public SpirvRelocation Relocation = new SpirvRelocation(-1, -1, -1);
            public uint StorageAlignment = 256;
            public ulong StorageRange = 1 << 27;
            public uint MaxImageDimension1D;
            public uint MaxImageDimension2D;
            public uint MaxImageDimension3D;
            public uint MaxImageDimensionCube;
            public uint MaxColorAttachments;
            public uint MaxUniformBuffersDynamic;
            public uint MaxStorageBuffersDynamic;
            public uint MaxPushConstantsSize;
            public uint MaxPushDescriptors;
            public uint MaxInlineUniformBlockSize;
            public uint MaxBoundDescriptorSets;
            public uint MaxViewports;
            public uint MaxVertexInputBindings;
            public uint MaxVertexInputAttributes;
            public uint MaxTransformFeedbackBuffers;
            public bool R8Storage;
            public bool Rg8Storage;
            public bool Etc2Transcode;
            public uint[] QueueFamilies = Array.Empty<uint>();
            public IntPtr Robustness2Name;
            public bool RobustImageAccess2;
            public bool NullDescriptor;
            public bool TimelineSemaphore;
        }

        private static string[] BuildCoreFeatures()
        {
            List<string> names = new List<string>();
            foreach (KeyValuePair<string, int> entry in BrovVulkLayout.MemberOffset)
            {
                if (entry.Key.StartsWith(FeaturePrefix, StringComparison.Ordinal))
                    names.Add(entry.Key.Substring(FeaturePrefix.Length));
            }

            names.Sort(StringComparer.Ordinal);
            return names.ToArray();
        }

        private static string[] ReadForced()
        {
            string? value = Environment.GetEnvironmentVariable(ForceVariable);
            return string.IsNullOrEmpty(value)
                ? Array.Empty<string>()
                : value.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        }

        private static int Offset(string name) => BrovVulkLayout.MemberOffset[FeaturePrefix + name];

        internal static DeviceGaps Gaps(IntPtr physicalDevice)
        {
            lock (Lock)
            {
                if (GapsByDevice.TryGetValue(physicalDevice, out DeviceGaps? cached) && cached != null)
                    return cached;

                int size = BrovVulkLayout.StructSize["VkPhysicalDeviceFeatures"];
                byte* host = stackalloc byte[size];
                new Span<byte>(host, size).Clear();
                BrovVulkApi.vkGetPhysicalDeviceFeatures(physicalDevice, (IntPtr)host);

                List<string> missing = new List<string>();
                foreach (string name in CoreFeatures)
                {
                    if (*(uint*)(host + Offset(name)) == 0)
                        missing.Add(name);
                }

                foreach (string name in Forced)
                {
                    if (Array.IndexOf(CoreFeatures, name) >= 0 && !missing.Contains(name))
                        missing.Add(name);
                }

                DeviceGaps gaps = new DeviceGaps { Missing = missing.ToArray() };
                foreach ((int bit, string name) in Features)
                {
                    if (missing.Contains(name))
                        gaps.ImplementedBits |= bit;
                }

                foreach ((int bit, string name) in HostAbilities)
                {
                    if (!missing.Contains(name))
                        gaps.HostBits |= bit;
                }

                ProbeLimits(physicalDevice, gaps);
                ProbeExtensions(physicalDevice, gaps);
                GapsByDevice[physicalDevice] = gaps;
                return gaps;
            }
        }

        private static void ProbeExtensions(IntPtr physicalDevice, DeviceGaps gaps)
        {
            gaps.HostExtensions = BrovVulkGenExt.QueryHost(physicalDevice);
            foreach ((int bit, string name, bool translates) in Extensions)
            {
                bool present = gaps.HostExtensions.ContainsKey(name) || (bit == LoadStoreOpNoneBit && gaps.HostExtensions.ContainsKey(LoadStoreOpNoneExt));
                if (!present || (translates && Array.IndexOf(Forced, name) >= 0))
                    gaps.ImplementedBits |= bit;
            }

            // Turning clipping off needs clamping in its place.
            if ((gaps.ImplementedBits & DepthClipEnableBit) != 0 && (gaps.HostBits & HostDepthClampBit) == 0)
                gaps.ImplementedBits &= ~DepthClipEnableBit;

            gaps.Robustness2Name = gaps.HostExtensions.ContainsKey("VK_KHR_robustness2") ? Robustness2KhrName
                : gaps.HostExtensions.ContainsKey("VK_EXT_robustness2") ? Robustness2ExtName : IntPtr.Zero;
            if (gaps.Robustness2Name != IntPtr.Zero)
            {
                byte* robustness = stackalloc byte[64];
                HostFeatures(physicalDevice, StPhysicalDeviceRobustness2FeaturesExt, robustness);
                if (*(uint*)(robustness + Robustness2BufferAccess2) == 0 || Array.IndexOf(Forced, RobustBufferAccess2Name) >= 0)
                    gaps.ImplementedBits |= RobustBufferAccess2Bit;
                gaps.RobustImageAccess2 = *(uint*)(robustness + Robustness2ImageAccess2) != 0;
                gaps.NullDescriptor = *(uint*)(robustness + Robustness2NullDescriptor) != 0;
            }

            if (gaps.ApiVersion >= ApiVersion12 || gaps.HostExtensions.ContainsKey("VK_KHR_timeline_semaphore"))
            {
                byte* timeline = stackalloc byte[64];
                HostFeatures(physicalDevice, StPhysicalDeviceTimelineSemaphoreFeatures, timeline);
                gaps.TimelineSemaphore = *(uint*)(timeline + TimelineFeature) != 0;
            }
        }

        internal static bool AdvertisesExtension(IntPtr physicalDevice, string name)
        {
            DeviceGaps gaps = Gaps(physicalDevice);
            if (name == LoadStoreOpNoneKhr || name == LoadStoreOpNoneExt)
                return true;

            foreach ((int bit, string candidate, _) in Extensions)
            {
                if (string.Equals(candidate, name, StringComparison.Ordinal))
                    return (gaps.ImplementedBits & bit) != 0;
            }

            return false;
        }

        private static void ProbeLimits(IntPtr physicalDevice, DeviceGaps gaps)
        {
            int size = BrovVulkLayout.StructSize["VkPhysicalDeviceProperties"];
            byte* properties = stackalloc byte[size];
            new Span<byte>(properties, size).Clear();
            BrovVulkApi.vkGetPhysicalDeviceProperties(physicalDevice, (IntPtr)properties);
            gaps.ApiVersion = *(uint*)(properties + BrovVulkGenExt.PropertiesApiVersion);
            if (*(int*)(properties + PropertiesDeviceType) == BrovVulkConstants.VK_PHYSICAL_DEVICE_TYPE_CPU || Array.IndexOf(Forced, CpuDeviceName) >= 0)
                gaps.HostBits |= HostCpuDeviceBit;
            byte* limits = properties + PropertiesLimits;

            ulong alignment = *(ulong*)(limits + LimitsStorageAlignment);
            if (alignment != 0 && alignment <= 4096 && (alignment & (alignment - 1)) == 0)
                gaps.StorageAlignment = (uint)alignment;
            uint range = *(uint*)(limits + LimitsStorageRange);
            if (range != 0)
                gaps.StorageRange = range;

            gaps.MaxImageDimension1D = *(uint*)(limits + LimitsImageDimension1D);
            gaps.MaxImageDimension2D = *(uint*)(limits + LimitsImageDimension2D);
            gaps.MaxImageDimension3D = *(uint*)(limits + LimitsImageDimension3D);
            gaps.MaxImageDimensionCube = *(uint*)(limits + LimitsImageDimensionCube);
            gaps.MaxColorAttachments = *(uint*)(limits + LimitsColorAttachments);
            gaps.MaxUniformBuffersDynamic = *(uint*)(limits + LimitsUniformBuffersDynamic);
            gaps.MaxStorageBuffersDynamic = *(uint*)(limits + LimitsStorageBuffersDynamic);
            gaps.MaxPushConstantsSize = *(uint*)(limits + LimitsPushConstantsSize);
            gaps.MaxBoundDescriptorSets = *(uint*)(limits + LimitsBoundDescriptorSets);
            gaps.MaxViewports = *(uint*)(limits + LimitsViewports);
            gaps.MaxVertexInputBindings = *(uint*)(limits + LimitsVertexInputBindings);
            gaps.MaxVertexInputAttributes = *(uint*)(limits + LimitsVertexInputAttributes);
            ProbeExtensionLimits(physicalDevice, gaps);

            if ((gaps.ImplementedBits & RelocationBits) != 0)
            {
                uint components = Math.Min(Math.Min(*(uint*)(limits + LimitsVertexOutputs), *(uint*)(limits + LimitsFragmentInputs)),
                    Math.Min(*(uint*)(limits + LimitsGeometryOutputs), *(uint*)(limits + LimitsTessellationOutputs)));
                int cap = (int)Math.Min(components / 4, MaxLocations);
                int viewport = cap - 1;
                int clip = cap - 1 - SpirvRelocation.MaxElements;
                int cull = clip - SpirvRelocation.MaxElements;
                gaps.Relocation = new SpirvRelocation(
                    (gaps.ImplementedBits & MultiViewportBit) != 0 && viewport >= 0 ? viewport : -1,
                    (gaps.ImplementedBits & ClipDistanceBit) != 0 && clip >= 0 ? clip : -1,
                    (gaps.ImplementedBits & CullDistanceBit) != 0 && cull >= 0 ? cull : -1);
            }

            if ((gaps.ImplementedBits & TextureCompressionBcBit) != 0)
            {
                gaps.R8Storage = SupportsStorage(physicalDevice, TextureCompressionBC.FormatR8Uint);
                gaps.Rg8Storage = SupportsStorage(physicalDevice, TextureCompressionBC.FormatRg8Uint);
                gaps.Etc2Transcode = MemoryBudget.Profile != MemoryProfile.Off
                    && SupportsTranscode(physicalDevice, TextureCompressionBC.FormatEtc2Rgba8Unorm)
                    && SupportsTranscode(physicalDevice, TextureCompressionBC.FormatEtc2Rgba8Srgb);

                uint count = 0;
                BrovVulkApi.vkGetPhysicalDeviceQueueFamilyProperties(physicalDevice, (IntPtr)(&count), IntPtr.Zero);
                if (count != 0 && count <= 64)
                {
                    byte* families = stackalloc byte[(int)count * QueueFamilySize];
                    new Span<byte>(families, (int)count * QueueFamilySize).Clear();
                    BrovVulkApi.vkGetPhysicalDeviceQueueFamilyProperties(physicalDevice, (IntPtr)(&count), (IntPtr)families);
                    gaps.QueueFamilies = new uint[count];
                    for (uint k = 0; k < count; k++)
                        gaps.QueueFamilies[k] = *(uint*)(families + k * QueueFamilySize + QueueFamilyFlags);
                }
            }
        }

        private static bool SupportsStorage(IntPtr physicalDevice, int format)
        {
            byte* properties = stackalloc byte[FormatPropertiesSize];
            new Span<byte>(properties, FormatPropertiesSize).Clear();
            BrovVulkApi.vkGetPhysicalDeviceFormatProperties(physicalDevice, format, (IntPtr)properties);
            return (*(uint*)(properties + FormatPropertiesOptimal) & TextureCompressionBC.FormatFeatureStorageImage) != 0;
        }

        // A transcode target is never written as a storage image, only sampled and copied into.
        private static bool SupportsTranscode(IntPtr physicalDevice, int format)
        {
            byte* properties = stackalloc byte[FormatPropertiesSize];
            new Span<byte>(properties, FormatPropertiesSize).Clear();
            BrovVulkApi.vkGetPhysicalDeviceFormatProperties(physicalDevice, format, (IntPtr)properties);
            return (*(uint*)(properties + FormatPropertiesOptimal) & TranscodeFeatures) == TranscodeFeatures;
        }

        internal static void Advertise(IntPtr physicalDevice, IntPtr features)
        {
            if (features == IntPtr.Zero)
                return;

            DeviceGaps gaps = Gaps(physicalDevice);
            Write(features, gaps, 1);
            HideSparse(gaps, features);
        }

        private static void HideSparse(DeviceGaps gaps, IntPtr block)
        {
            if ((gaps.HostBits & HostCpuDeviceBit) == 0 || block == IntPtr.Zero)
                return;

            foreach (string name in SparseFeatures)
                *(uint*)((byte*)block + Offset(name)) = 0;
        }

        internal static void Advertise2(IntPtr physicalDevice, IntPtr features2)
        {
            if (features2 == IntPtr.Zero)
                return;

            DeviceGaps gaps = Gaps(physicalDevice);
            Write(features2 + FeatureBits, gaps, 1);
            HideSparse(gaps, features2 + FeatureBits);
            for (IntPtr node = *(IntPtr*)(features2 + VkOffsets.NodePNext); node != IntPtr.Zero; node = *(IntPtr*)(node + VkOffsets.NodePNext))
            {
                if ((gaps.HostBits & HostCpuDeviceBit) != 0)
                    ClearCpuWithheld(node);
                switch (*(uint*)node)
                {
                    case StPhysicalDeviceVulkan12Features:
                        if ((gaps.ImplementedBits & MultiDrawIndirectBit) != 0)
                            *(uint*)(node + Vulkan12DrawIndirectCount) = 0;
                        break;
                    case StPhysicalDeviceVulkan14Features:
                        if ((gaps.ImplementedBits & Maintenance5Bit) != 0)
                            *(uint*)(node + Vulkan14Maintenance5) = 1;
                        if ((gaps.ImplementedBits & Maintenance6Bit) != 0)
                            *(uint*)(node + Vulkan14Maintenance6) = 1;
                        break;
                    case StPhysicalDeviceMaintenance5Features:
                        if ((gaps.ImplementedBits & Maintenance5Bit) != 0)
                            *(uint*)(node + Maintenance5Feature) = 1;
                        break;
                    case StPhysicalDeviceMaintenance6Features:
                        if ((gaps.ImplementedBits & Maintenance6Bit) != 0)
                            *(uint*)(node + Maintenance6Feature) = 1;
                        break;
                    case StPhysicalDeviceDepthClipEnableFeaturesExt:
                        if ((gaps.ImplementedBits & DepthClipEnableBit) != 0)
                            *(uint*)(node + DepthClipEnableFeature) = 1;
                        break;
                    case StPhysicalDeviceRobustness2FeaturesExt:
                        if ((gaps.ImplementedBits & RobustBufferAccess2Bit) != 0)
                            *(uint*)(node + Robustness2BufferAccess2) = 1;
                        break;
                }
            }
        }

        internal static void Properties(IntPtr physicalDevice, IntPtr properties)
        {
            if (properties == IntPtr.Zero)
                return;

            DeviceGaps gaps = Gaps(physicalDevice);
            if ((gaps.ImplementedBits & MultiDrawIndirectBit) != 0)
                *(uint*)(properties + PropertiesLimits + LimitsDrawIndirectCount) = MaxStandInDrawCount;
            if ((gaps.ImplementedBits & SamplerAnisotropyBit) != 0)
                *(float*)(properties + PropertiesLimits + LimitsSamplerAnisotropy) = 16f;
        }

        internal static void Properties2(IntPtr physicalDevice, IntPtr properties2)
        {
            if (properties2 == IntPtr.Zero)
                return;

            Properties(physicalDevice, properties2 + Properties2Properties);
            DeviceGaps gaps = Gaps(physicalDevice);
            for (IntPtr node = *(IntPtr*)(properties2 + VkOffsets.NodePNext); node != IntPtr.Zero; node = *(IntPtr*)(node + VkOffsets.NodePNext))
            {
                switch (*(uint*)node)
                {
                    case StPhysicalDeviceMaintenance5Properties:
                        if ((gaps.ImplementedBits & Maintenance5Bit) != 0)
                            new Span<byte>((void*)(node + FeatureBits), Maintenance5PropertiesSize - FeatureBits).Clear();
                        break;
                    case StPhysicalDeviceMaintenance6Properties:
                        if ((gaps.ImplementedBits & Maintenance6Bit) != 0)
                            Maintenance6.Properties(node);
                        break;
                }
            }
        }

        // A format the host cannot know becomes UNDEFINED.
        internal static int QueryFormat(IntPtr physicalDevice, int format)
        {
            return Maintenance5.IsNewFormat(format) && (Gaps(physicalDevice).ImplementedBits & Maintenance5Bit) != 0 ? 0 : format;
        }

        /// <summary>
        /// Clears the features the driver would reject from a VkDeviceCreateInfo, turns on what the stand-ins
        /// need, and returns the stand-in and host ability bits for the device.
        /// </summary>
        internal static int StripDeviceFeatures(GenState st, IntPtr physicalDevice, IntPtr createInfo)
        {
            DeviceGaps gaps = Gaps(physicalDevice);
            int bits = gaps.ImplementedBits | gaps.HostBits;
            if (gaps.ImplementedBits != 0)
                Any = true;
            if ((gaps.ImplementedBits & FillModeNonSolidBit) != 0)
                st.StandIns.WireframeActive = true;
            if ((gaps.ImplementedBits & ClipDistanceBit) != 0)
                st.StandIns.ClipActive = true;
            if ((gaps.ImplementedBits & TextureCompressionBcBit) != 0)
                st.StandIns.CompressionActive = true;
            if (createInfo == IntPtr.Zero)
                return bits;

            ClampToHost(physicalDevice, createInfo);
            StripExtensions(st, gaps, createInfo);

            IntPtr enabled = *(IntPtr*)((byte*)createInfo + DeviceCreateInfoEnabledFeatures);
            Write(enabled, gaps, 0);

            // VkPhysicalDeviceFeatures2 carries the same block and wins over pEnabledFeatures.
            IntPtr block = IntPtr.Zero;
            for (IntPtr next = *(IntPtr*)((byte*)createInfo + DeviceCreateInfoPNext); next != IntPtr.Zero; next = *(IntPtr*)((byte*)next + VkOffsets.NodePNext))
            {
                if (*(uint*)next != StPhysicalDeviceFeatures2)
                    continue;

                block = next + FeatureBits;
                Write(block, gaps, 0);
            }

            // Depth clipping is turned off with the clamp, so the device has to enable it.
            int need = (gaps.ImplementedBits & FillModeNonSolidBit) != 0
                ? HostGeometryShaderBit | HostGeometryPointSizeBit : 0;
            if ((gaps.ImplementedBits & DepthClipEnableBit) != 0)
                need |= HostDepthClampBit;

            if (need != 0)
            {
                if (block == IntPtr.Zero)
                    block = enabled;
                if (block == IntPtr.Zero)
                {
                    block = st.Alloc(BrovVulkLayout.StructSize["VkPhysicalDeviceFeatures"]);
                    *(IntPtr*)((byte*)createInfo + DeviceCreateInfoEnabledFeatures) = block;
                }

                foreach ((int bit, string name) in HostAbilities)
                {
                    if ((gaps.HostBits & bit) != 0 && (need & bit) != 0)
                        *(uint*)((byte*)block + Offset(name)) = 1;
                }
            }

            if ((gaps.HostBits & HostCpuDeviceBit) != 0)
                ForceCpuDevice(st, gaps, createInfo);

            Report(gaps);
            return bits;
        }

        private static void ForceCpuDevice(GenState st, DeviceGaps gaps, IntPtr createInfo)
        {
            if (Array.IndexOf(gaps.Missing, "robustBufferAccess") >= 0 || gaps.Robustness2Name == IntPtr.Zero || !gaps.RobustImageAccess2 || !gaps.TimelineSemaphore)
                throw new InvalidOperationException("BrovVulk generic: a CPU device needs robustBufferAccess, robustImageAccess2 and timelineSemaphore, and this driver lacks one.");

            IntPtr block = *(IntPtr*)((byte*)createInfo + DeviceCreateInfoEnabledFeatures);
            IntPtr robustness = IntPtr.Zero;
            IntPtr timeline = IntPtr.Zero;
            for (IntPtr node = *(IntPtr*)((byte*)createInfo + DeviceCreateInfoPNext); node != IntPtr.Zero; node = *(IntPtr*)(node + VkOffsets.NodePNext))
            {
                ClearCpuWithheld(node);
                switch (*(uint*)node)
                {
                    case StPhysicalDeviceFeatures2:
                        block = node + FeatureBits;
                        break;
                    case StPhysicalDeviceRobustness2FeaturesExt:
                        robustness = node;
                        break;
                    case StPhysicalDeviceVulkan12Features:
                        timeline = node + Vulkan12Timeline;
                        break;
                    case StPhysicalDeviceTimelineSemaphoreFeatures:
                        timeline = node + TimelineFeature;
                        break;
                }
            }

            if (block == IntPtr.Zero)
            {
                block = st.Alloc(BrovVulkLayout.StructSize["VkPhysicalDeviceFeatures"]);
                *(IntPtr*)((byte*)createInfo + DeviceCreateInfoEnabledFeatures) = block;
            }
            *(uint*)((byte*)block + Offset("robustBufferAccess")) = 1;
            HideSparse(gaps, block);

            if (timeline == IntPtr.Zero)
            {
                IntPtr node = st.Alloc(TimelineFeaturesSize);
                *(uint*)node = StPhysicalDeviceTimelineSemaphoreFeatures;
                *(IntPtr*)(node + VkOffsets.NodePNext) = *(IntPtr*)((byte*)createInfo + DeviceCreateInfoPNext);
                *(IntPtr*)((byte*)createInfo + DeviceCreateInfoPNext) = node;
                timeline = node + TimelineFeature;
                if (gaps.HostExtensions.ContainsKey("VK_KHR_timeline_semaphore"))
                    EnsureExtension(st, createInfo, TimelineSemaphoreName, "VK_KHR_timeline_semaphore");
            }
            *(uint*)timeline = 1;

            if (robustness == IntPtr.Zero)
            {
                robustness = st.Alloc(Robustness2Size);
                *(uint*)robustness = StPhysicalDeviceRobustness2FeaturesExt;
                *(IntPtr*)(robustness + VkOffsets.NodePNext) = *(IntPtr*)((byte*)createInfo + DeviceCreateInfoPNext);
                *(IntPtr*)((byte*)createInfo + DeviceCreateInfoPNext) = robustness;
            }
            *(uint*)(robustness + Robustness2ImageAccess2) = 1;
            if ((gaps.ImplementedBits & RobustBufferAccess2Bit) == 0)
                *(uint*)(robustness + Robustness2BufferAccess2) = 1;
            if (gaps.NullDescriptor)
                *(uint*)(robustness + Robustness2NullDescriptor) = 1;

            EnsureExtension(st, createInfo, gaps.Robustness2Name, "VK_KHR_robustness2", "VK_EXT_robustness2");
        }

        private static void EnsureExtension(GenState st, IntPtr createInfo, IntPtr name, params string[] equivalent)
        {
            foreach (string enabled in equivalent)
            {
                if (BrovVulkGenMemory.EnablesExtension(createInfo, enabled))
                    return;
            }

            uint count = *(uint*)((byte*)createInfo + DeviceCreateInfoExtensionCount);
            IntPtr names = *(IntPtr*)((byte*)createInfo + DeviceCreateInfoExtensionNames);
            IntPtr grown = st.Alloc(BrovVulkGenStruct.CheckedBytes(count + 1, 8));
            for (uint k = 0; k < count; k++)
                *(IntPtr*)(grown + (int)(k * 8)) = *(IntPtr*)(names + (int)(k * 8));
            *(IntPtr*)(grown + (int)(count * 8)) = name;
            *(uint*)((byte*)createInfo + DeviceCreateInfoExtensionCount) = count + 1;
            *(IntPtr*)((byte*)createInfo + DeviceCreateInfoExtensionNames) = grown;
        }

        internal static bool WithholdsExtension(IntPtr physicalDevice, string name) =>
            (Gaps(physicalDevice).HostBits & HostCpuDeviceBit) != 0 && Array.IndexOf(BrovVulkExtensions.CpuWithheld, name) >= 0;

        private static void Write(IntPtr features, DeviceGaps gaps, uint value)
        {
            if (features == IntPtr.Zero)
                return;

            foreach ((int bit, string name) in Features)
            {
                if ((gaps.ImplementedBits & bit) != 0)
                    *(uint*)((byte*)features + Offset(name)) = value;
            }

            if (!Relax)
                return;

            foreach (string name in gaps.Missing)
                *(uint*)((byte*)features + Offset(name)) = value;
        }

        private static bool Reported;

        private static void Report(DeviceGaps gaps)
        {
            if (Reported)
                return;
            Reported = true;

            string implemented = string.Empty;
            foreach ((int bit, string name) in Features)
            {
                if ((gaps.ImplementedBits & bit) != 0)
                    implemented += implemented.Length != 0 ? ", " + name : name;
            }

            foreach ((int bit, string name, _) in Extensions)
            {
                if ((gaps.ImplementedBits & bit) != 0)
                    implemented += implemented.Length != 0 ? ", " + name : name;
            }

            if ((gaps.ImplementedBits & RobustBufferAccess2Bit) != 0)
                implemented += (implemented.Length != 0 ? ", " : string.Empty) + RobustBufferAccess2Name + " (bounded by robustBufferAccess only)";

            if (implemented.Length != 0)
                Utils.LogError("[VulkanImpls] standing in for: " + implemented + ".");

            if (!Relax || gaps.Missing.Length == 0)
                return;

            string claimed = string.Empty;
            foreach (string name in gaps.Missing)
            {
                if ((gaps.ImplementedBits & BitOf(name)) != 0)
                    continue;
                claimed += claimed.Length != 0 ? ", " + name : name;
            }

            if (claimed.Length != 0)
                Utils.LogError("[VulkanImpls] claimed with no implementation: " + claimed + ".");
        }

        private static int BitOf(string name)
        {
            foreach ((int bit, string candidate) in Features)
            {
                if (string.Equals(candidate, name, StringComparison.Ordinal))
                    return bit;
            }
            return 0;
        }

        // A chained feature bit the driver lacks fails the whole vkCreateDevice, so the request is clamped to the host.
        private static readonly (uint SType, int Count)[] ChainedFeatures =
        {
            (StPhysicalDeviceTransformFeedbackFeaturesExt, 2),
            (StPhysicalDeviceRobustness2FeaturesExt, 3),
        };

        private static void ClampToHost(IntPtr physicalDevice, IntPtr createInfo)
        {
            byte* supported = stackalloc byte[64];
            for (IntPtr node = *(IntPtr*)((byte*)createInfo + DeviceCreateInfoPNext); node != IntPtr.Zero; node = *(IntPtr*)((byte*)node + VkOffsets.NodePNext))
            {
                uint sType = *(uint*)node;
                int count = 0;
                foreach ((uint known, int bits) in ChainedFeatures)
                {
                    if (known == sType)
                        count = bits;
                }

                if (count == 0)
                    continue;

                byte* wanted = (byte*)node + FeatureBits;
                HostFeatures(physicalDevice, sType, supported);

                for (int i = 0; i < count; i++)
                {
                    uint* bit = (uint*)(wanted + i * 4);
                    if (*bit == 0 || *(uint*)(supported + FeatureBits + i * 4) != 0)
                        continue;

                    *bit = 0;
                    Utils.LogError($"[VulkanImpls] cleared feature {i} of sType {sType}, the driver does not have it.");
                }
            }
        }

        private static void HostFeatures(IntPtr physicalDevice, uint sType, byte* node)
        {
            new Span<byte>(node, 64).Clear();
            *(uint*)node = sType;

            byte* head = stackalloc byte[256];
            new Span<byte>(head, 256).Clear();
            *(uint*)head = StPhysicalDeviceFeatures2;
            *(IntPtr*)(head + VkOffsets.NodePNext) = (IntPtr)node;

            BrovVulkApi.vkGetPhysicalDeviceFeatures2(physicalDevice, (IntPtr)head);
        }

        // The driver rejects an extension name it does not know, and the feature structs that go with it.
        private static void StripExtensions(GenState st, DeviceGaps gaps, IntPtr createInfo)
        {
            uint count = *(uint*)((byte*)createInfo + DeviceCreateInfoExtensionCount);
            IntPtr names = *(IntPtr*)((byte*)createInfo + DeviceCreateInfoExtensionNames);
            if (count != 0 && names != IntPtr.Zero)
            {
                IntPtr kept = st.Alloc(BrovVulkGenStruct.CheckedBytes(count, 8));
                uint n = 0;
                bool loadStoreKept = false;
                for (uint k = 0; k < count; k++)
                {
                    IntPtr name = *(IntPtr*)(names + (int)(k * 8));
                    IntPtr forHost = ExtensionForHost(gaps, name, ref loadStoreKept);
                    if (forHost != IntPtr.Zero)
                        *(IntPtr*)(kept + (int)(n++ * 8)) = forHost;
                }

                *(uint*)((byte*)createInfo + DeviceCreateInfoExtensionCount) = n;
                *(IntPtr*)((byte*)createInfo + DeviceCreateInfoExtensionNames) = kept;
            }

            IntPtr* link = (IntPtr*)((byte*)createInfo + DeviceCreateInfoPNext);
            while (*link != IntPtr.Zero)
            {
                IntPtr node = *link;
                uint sType = *(uint*)node;
                bool drop = (sType == StPhysicalDeviceMaintenance5Features && (gaps.ImplementedBits & Maintenance5Bit) != 0)
                    || (sType == StPhysicalDeviceMaintenance6Features && (gaps.ImplementedBits & Maintenance6Bit) != 0)
                    || (sType == StPhysicalDeviceDepthClipEnableFeaturesExt && (gaps.ImplementedBits & DepthClipEnableBit) != 0);
                if (drop)
                {
                    *link = *(IntPtr*)(node + VkOffsets.NodePNext);
                    continue;
                }

                if (sType == StPhysicalDeviceVulkan14Features)
                {
                    if ((gaps.ImplementedBits & Maintenance5Bit) != 0)
                        *(uint*)(node + Vulkan14Maintenance5) = 0;
                    if ((gaps.ImplementedBits & Maintenance6Bit) != 0)
                        *(uint*)(node + Vulkan14Maintenance6) = 0;
                }
                else if (sType == StPhysicalDeviceVulkan12Features && (gaps.ImplementedBits & MultiDrawIndirectBit) != 0)
                {
                    *(uint*)(node + Vulkan12DrawIndirectCount) = 0;
                }

                link = (IntPtr*)(node + VkOffsets.NodePNext);
            }
        }

        private static IntPtr ExtensionForHost(DeviceGaps gaps, IntPtr name, ref bool loadStoreKept)
        {
            string? text = Marshal.PtrToStringAnsi(name);
            if (text == null)
                return name;

            if (text == LoadStoreOpNoneKhr || text == LoadStoreOpNoneExt)
            {
                if ((gaps.ImplementedBits & LoadStoreOpNoneBit) != 0 || loadStoreKept)
                    return IntPtr.Zero;

                loadStoreKept = true;
                return gaps.HostExtensions.ContainsKey(text) ? name
                    : gaps.HostExtensions.ContainsKey(LoadStoreOpNoneExt) ? LoadStoreOpNoneExtName
                    : LoadStoreOpNoneKhrName;
            }

            foreach ((int bit, string candidate, _) in Extensions)
            {
                if (string.Equals(candidate, text, StringComparison.Ordinal))
                    return (gaps.ImplementedBits & bit) != 0 ? IntPtr.Zero : name;
            }

            return name;
        }

        private static bool Compression(IntPtr physicalDevice, out DeviceGaps gaps)
        {
            gaps = null!;
            if (!Any && Forced.Length == 0)
                return false;

            gaps = Gaps(physicalDevice);
            return (gaps.ImplementedBits & TextureCompressionBcBit) != 0;
        }

        internal static void FormatProperties(IntPtr physicalDevice, int format, IntPtr properties)
        {
            if (properties != IntPtr.Zero && TextureCompressionBC.IsCompressed(format) && Compression(physicalDevice, out DeviceGaps gaps))
                TextureCompressionBC.FormatProperties(physicalDevice, gaps, format, properties);
        }

        internal static void FormatProperties2(IntPtr physicalDevice, int format, IntPtr properties)
        {
            if (properties != IntPtr.Zero && TextureCompressionBC.IsCompressed(format) && Compression(physicalDevice, out DeviceGaps gaps))
                TextureCompressionBC.FormatProperties2(physicalDevice, gaps, format, properties);
        }

        internal static int ImageFormatProperties(IntPtr physicalDevice, ref int format, int type, int tiling, ref uint usage, ref uint flags)
        {
            if (Maintenance5.IsNewFormat(format))
                return (Gaps(physicalDevice).ImplementedBits & Maintenance5Bit) != 0 ? ErrorFormatNotSupported : 0;

            if (!TextureCompressionBC.IsCompressed(format) || !Compression(physicalDevice, out DeviceGaps gaps))
                return 0;

            return TextureCompressionBC.ImageFormatProperties(gaps, ref format, type, tiling, ref usage, ref flags);
        }

        // Format limits can exceed device limits (VUID-02252 to -02255).
        internal static bool ImageExtentFits(IntPtr physicalDevice, IntPtr createInfo)
        {
            DeviceGaps gaps = Gaps(physicalDevice);
            int type = *(int*)(createInfo + VkOffsets.ImageType);
            uint flags = *(uint*)(createInfo + VkOffsets.ImageFlags);
            uint width = *(uint*)(createInfo + VkOffsets.ImageWidth);
            uint height = *(uint*)(createInfo + VkOffsets.ImageHeight);
            uint depth = *(uint*)(createInfo + VkOffsets.ImageDepth);

            uint limit = type switch
            {
                BrovVulkConstants.VK_IMAGE_TYPE_1D => gaps.MaxImageDimension1D,
                BrovVulkConstants.VK_IMAGE_TYPE_2D => (flags & BrovVulkConstants.VK_IMAGE_CREATE_CUBE_COMPATIBLE_BIT) != 0
                    ? gaps.MaxImageDimensionCube
                    : gaps.MaxImageDimension2D,
                BrovVulkConstants.VK_IMAGE_TYPE_3D => gaps.MaxImageDimension3D,
                _ => 0,
            };
            if (limit == 0)
                return false;

            uint heightLimit = type == BrovVulkConstants.VK_IMAGE_TYPE_1D ? 1 : limit;
            uint depthLimit = type == BrovVulkConstants.VK_IMAGE_TYPE_3D ? limit : 1;
            if (width <= limit && height <= heightLimit && depth <= depthLimit)
                return true;

            int tiling = *(int*)(createInfo + VkOffsets.ImageTiling);
            if (tiling != BrovVulkConstants.VK_IMAGE_TILING_OPTIMAL && tiling != BrovVulkConstants.VK_IMAGE_TILING_LINEAR)
                return false;

            int format = *(int*)(createInfo + VkOffsets.ImageFormat);
            uint usage = *(uint*)(createInfo + VkOffsets.ImageUsage);
            if (ImageFormatProperties(physicalDevice, ref format, type, tiling, ref usage, ref flags) < 0)
                return false;

            byte* properties = stackalloc byte[ImageFormatPropertiesSize];
            new Span<byte>(properties, ImageFormatPropertiesSize).Clear();
            if (BrovVulkApi.vkGetPhysicalDeviceImageFormatProperties(physicalDevice, format, type, tiling, usage, flags, (IntPtr)properties) != 0)
                return false;

            return width <= *(uint*)(properties + ImageFormatMaxWidth) && height <= *(uint*)(properties + ImageFormatMaxHeight)
                && depth <= *(uint*)(properties + ImageFormatMaxDepth)
                && *(uint*)(createInfo + VkOffsets.ImageMipLevels) <= *(uint*)(properties + ImageFormatMaxMipLevels);
        }

        internal static int ImageFormatProperties2(GenState st, IntPtr physicalDevice, IntPtr info)
        {
            if (info == IntPtr.Zero)
                return 0;

            int format = *(int*)(info + VkOffsets.ImageFormatInfoFormat);
            if (Maintenance5.IsNewFormat(format))
                return (Gaps(physicalDevice).ImplementedBits & Maintenance5Bit) != 0 ? ErrorFormatNotSupported : 0;

            if (!TextureCompressionBC.IsCompressed(format) || !Compression(physicalDevice, out DeviceGaps gaps))
                return 0;

            return TextureCompressionBC.ImageFormatProperties2(st, gaps, info);
        }

        internal static void QueueFamilyProperties(IntPtr physicalDevice, uint count, IntPtr properties, int stride, int flagsOffset)
        {
            if (properties == IntPtr.Zero)
                return;

            if ((Gaps(physicalDevice).HostBits & HostCpuDeviceBit) != 0)
            {
                for (uint k = 0; k < count; k++)
                    *(uint*)(properties + (int)(k * (uint)stride) + flagsOffset) &= ~(uint)BrovVulkConstants.VK_QUEUE_SPARSE_BINDING_BIT;
            }

            if (!Compression(physicalDevice, out _))
                return;

            // The decoder is a compute dispatch, so a family without compute must not attract the guest's copies.
            for (uint k = 0; k < count; k++)
            {
                uint* flags = (uint*)(properties + (int)(k * (uint)stride) + flagsOffset);
                if ((*flags & (QueueGraphics | QueueCompute)) == 0)
                    *flags &= ~QueueTransfer;
            }
        }

        internal static void PatchShaderModule(GenState st, IntPtr device, IntPtr createInfo)
        {
            int bits = st.DeviceStandIns(device);
            if ((bits & RelocationBits) == 0)
                return;

            ulong size = *(ulong*)(createInfo + VkOffsets.ShaderModuleCodeSize);
            IntPtr code = *(IntPtr*)(createInfo + VkOffsets.ShaderModuleCode);
            if (code == IntPtr.Zero || size < 20 || (size & 3) != 0 || size > int.MaxValue)
                return;

            ShaderPatches.Relocate(st, device, (uint*)code, (int)(size / 4), out _);
        }

        internal static void NoteShaderModule(GenState st, IntPtr device, IntPtr createInfo, IntPtr module)
        {
            int bits = st.DeviceStandIns(device);
            if ((bits & (FillModeNonSolidBit | ClipDistanceBit | HostCpuDeviceBit)) == 0)
                return;

            ulong size = *(ulong*)(createInfo + VkOffsets.ShaderModuleCodeSize);
            IntPtr code = *(IntPtr*)(createInfo + VkOffsets.ShaderModuleCode);
            if (code == IntPtr.Zero || size < 20 || (size & 3) != 0 || size > int.MaxValue)
                return;

            ShaderPatches.NoteModule(st.StandIns, device, bits, (uint*)code, (int)(size / 4), module);
        }

        internal static void ForgetShaderModule(GenState st, IntPtr module) => st.StandIns.Modules.Remove(module);

        internal static void PreparePipelines(GenState st, IntPtr device, IntPtr createInfos, uint count, int stride)
        {
            int bits = st.DeviceStandIns(device);
            if ((bits & (PipelineBits | HostCpuDeviceBit)) == 0 || createInfos == IntPtr.Zero || stride <= 0)
                return;
            if ((bits & HostCpuDeviceBit) != 0)
                st.BeginPipelines(count);

            try
            {
                PrepareEachPipeline(st, device, bits, createInfos, count, stride);
            }
            catch
            {
                FinishPipelines(st, device, IntPtr.Zero, IntPtr.Zero, BrovVulkConstants.VK_ERROR_INITIALIZATION_FAILED);
                st.DropPendingPipelines();
                throw;
            }
        }

        private static void PrepareEachPipeline(GenState st, IntPtr device, int bits, IntPtr createInfos, uint count, int stride)
        {
            // The flag fold runs first so the later passes read the pipeline flags, and inline code becomes
            // modules so they find it where a guest made module would be.
            for (uint i = 0; i < count; i++)
            {
                IntPtr info = createInfos + (int)(i * (uint)stride);
                // pStages is optional, so stageCount can be non-zero with no array behind it.
                bool noStages = *(IntPtr*)(info + VkOffsets.PipelineStages) == IntPtr.Zero && *(uint*)(info + VkOffsets.PipelineStageCount) != 0;

                if ((bits & Maintenance5Bit) != 0)
                {
                    Maintenance5.FoldCreateFlags(info, VkOffsets.PipelineFlags);
                    if (!noStages)
                        Maintenance5.MaterializeModules(st, device, *(IntPtr*)(info + VkOffsets.PipelineStages), *(uint*)(info + VkOffsets.PipelineStageCount));
                }

                if ((bits & HostCpuDeviceBit) != 0)
                {
                    IntPtr layout = *(IntPtr*)(info + VkOffsets.PipelineLayout);
                    HashSet<uint> used = st.PipelineUse((int)i, layout, CreatesLibrary(info) ? GenState.PipelineLibrary : GenState.PipelineGraphics);
                    UseLibraries(st, info, (int)i);
                    if (!noStages)
                        BoundStages(st, device, *(IntPtr*)(info + VkOffsets.PipelineStages), *(uint*)(info + VkOffsets.PipelineStageCount), layout, used);
                    st.ResolvePipelineUse((int)i);
                }

                if (noStages)
                    continue;

                if ((bits & RelocationBits) != 0)
                    ShaderPatches.PreparePipeline(st, device, bits, info);

                if ((bits & DepthClipEnableBit) != 0)
                    DepthClipEnable.PatchPipeline(info);

                if ((bits & MultiViewportBit) != 0)
                    MultiViewport.PatchPipeline(info);

                if ((bits & FillModeNonSolidBit) != 0)
                    FillModeNonSolid.PreparePipeline(st.StandIns, st, device, bits, info, (int)i);
            }
        }

        // VkPipelineCreateFlags2CreateInfo replaces the flags member when it is in the chain.
        private static bool CreatesLibrary(IntPtr info)
        {
            for (IntPtr node = *(IntPtr*)(info + VkOffsets.NodePNext); node != IntPtr.Zero; node = *(IntPtr*)(node + VkOffsets.NodePNext))
            {
                if (*(int*)node == BrovVulkConstants.VK_STRUCTURE_TYPE_PIPELINE_CREATE_FLAGS_2_CREATE_INFO)
                    return (*(ulong*)(node + VkOffsets.CreateFlags2) & BrovVulkConstants.VK_PIPELINE_CREATE_LIBRARY_BIT_KHR) != 0;
            }
            return (*(uint*)(info + VkOffsets.PipelineFlags) & BrovVulkConstants.VK_PIPELINE_CREATE_LIBRARY_BIT_KHR) != 0;
        }

        internal static void FinishPipelines(GenState st, IntPtr device, IntPtr cache, IntPtr pipelines, int result)
        {
            if (st.StandIns.Plans.Count == 0 && st.StandIns.TemporaryModules.Count == 0)
                return;

            foreach (IntPtr module in st.StandIns.TemporaryModules)
                st.StandIns.Modules.Remove(module);
            FillModeNonSolid.FinishPipelines(st.StandIns, st, device, cache, pipelines, result);
        }

        internal static void PrepareComputePipelines(GenState st, IntPtr device, IntPtr createInfos, uint count, int stride)
        {
            int bits = st.DeviceStandIns(device);
            if ((bits & (Maintenance5Bit | HostCpuDeviceBit)) == 0 || createInfos == IntPtr.Zero || stride <= 0)
                return;
            if ((bits & HostCpuDeviceBit) != 0)
                st.BeginPipelines(count);

            try
            {
                for (uint i = 0; i < count; i++)
                {
                    IntPtr info = createInfos + (int)(i * (uint)stride);
                    if ((bits & Maintenance5Bit) != 0)
                    {
                        Maintenance5.FoldCreateFlags(info, VkOffsets.ComputePipelineFlags);
                        Maintenance5.MaterializeModules(st, device, info + VkOffsets.ComputePipelineStage, 1);
                    }
                    if ((bits & HostCpuDeviceBit) != 0)
                    {
                        IntPtr layout = *(IntPtr*)(info + VkOffsets.ComputePipelineLayout);
                        BoundStages(st, device, info + VkOffsets.ComputePipelineStage, 1, layout, st.PipelineUse((int)i, layout, GenState.PipelineCompute));
                        st.ResolvePipelineUse((int)i);
                    }
                }
            }
            catch
            {
                FinishComputePipelines(st, device);
                st.DropPendingPipelines();
                throw;
            }
        }

        // Later stand-ins must patch the bounded module.
        private static void BoundStages(GenState st, IntPtr device, IntPtr stages, uint count, IntPtr layout, HashSet<uint> used)
        {
            if (stages == IntPtr.Zero)
                return;

            BrovVulkAddressSpace? addresses = st.Retire.AddressSpaceOf(device);
            SpirvBounds.BindingInfo binding = (uint set, uint b, out long count, out int type) => st.LayoutBinding(layout, set, b, out count, out type);
            for (uint i = 0; i < count; i++)
            {
                IntPtr stage = stages + (int)(i * (uint)VkOffsets.StageSize);
                IntPtr module = *(IntPtr*)(stage + VkOffsets.StageModule);
                byte* namePtr = *(byte**)(stage + VkOffsets.StageName);
                ReadOnlySpan<byte> entry = namePtr != null ? MemoryMarshal.CreateReadOnlySpanFromNullTerminated(namePtr) : default;
                uint stageBit = *(uint*)(stage + VkOffsets.StageStage);
                IntPtr inline = IntPtr.Zero;
                ShaderModuleRecord? record = null;
                uint[]? bounded;
                string? refusal;
                if (module != IntPtr.Zero)
                {
                    if (!st.StandIns.Modules.TryGetValue(module, out record) || record.Code == null)
                        throw new InvalidOperationException("BrovVulk generic: a pipeline stage names a shader module this layer did not keep.");
                    fixed (uint* code = record.Code)
                        bounded = SpirvBounds.Bound(code, record.Code.Length, entry, stageBit, binding, addresses, used, out refusal);
                }
                else
                {
                    inline = ShaderPatches.InlineModule(stage);
                    if (inline == IntPtr.Zero)
                        throw new InvalidOperationException("BrovVulk generic: a pipeline stage has neither a module nor inline code.");
                    ulong size = *(ulong*)(inline + VkOffsets.ShaderModuleCodeSize);
                    IntPtr code = *(IntPtr*)(inline + VkOffsets.ShaderModuleCode);
                    if (code == IntPtr.Zero || size < 20 || (size & 3) != 0 || size > int.MaxValue)
                        throw new InvalidOperationException("BrovVulk generic: inline shader code of a bad size.");
                    bounded = SpirvBounds.Bound((uint*)code, (int)(size / 4), entry, stageBit, binding, addresses, used, out refusal);
                }

                if (refusal != null)
                    throw new InvalidOperationException("BrovVulk generic: " + refusal + ".");
                if (bounded == null)
                    continue;

                IntPtr temporary = ShaderPatches.CreateModule(st, device, bounded);
                if (temporary == IntPtr.Zero)
                    throw new InvalidOperationException("BrovVulk generic: the host refused a bounded shader module.");
                st.StandIns.Modules[temporary] = new ShaderModuleRecord
                {
                    Device = device, Models = record?.Models ?? 0, ClipOutputs = record?.ClipOutputs ?? 0,
                    InterfaceModel = record?.InterfaceModel ?? 0, Interface = record?.Interface, Code = bounded,
                };
                st.StandIns.TemporaryModules.Add(temporary);
                *(IntPtr*)(stage + VkOffsets.StageModule) = temporary;
                if (inline != IntPtr.Zero)
                    ShaderPatches.UnlinkInlineModules(stage);
            }
        }

        private static void UseLibraries(GenState st, IntPtr info, int index)
        {
            for (IntPtr node = *(IntPtr*)(info + VkOffsets.NodePNext); node != IntPtr.Zero; node = *(IntPtr*)(node + VkOffsets.NodePNext))
            {
                if (*(int*)node != BrovVulkConstants.VK_STRUCTURE_TYPE_PIPELINE_LIBRARY_CREATE_INFO_KHR)
                    continue;
                uint count = *(uint*)(node + VkOffsets.LibraryCount);
                IntPtr* libraries = *(IntPtr**)(node + VkOffsets.LibraryHandles);
                for (uint k = 0; libraries != null && k < count; k++)
                    st.UseLibrary(index, libraries[k]);
            }
        }


        internal static void PrepareStagePipelines(GenState st, IntPtr device, IntPtr createInfos, uint count, int stride, int flagsOffset, int stagesOffset, int stageCountOffset)
        {
            if ((st.DeviceStandIns(device) & Maintenance5Bit) == 0 || createInfos == IntPtr.Zero || stride <= 0)
                return;

            for (uint i = 0; i < count; i++)
            {
                IntPtr info = createInfos + (int)(i * (uint)stride);
                Maintenance5.FoldCreateFlags(info, flagsOffset);
                Maintenance5.MaterializeModules(st, device, *(IntPtr*)(info + stagesOffset), *(uint*)(info + stageCountOffset));
            }
        }

        internal static void FinishComputePipelines(GenState st, IntPtr device)
        {
            foreach (IntPtr module in st.StandIns.TemporaryModules)
            {
                st.StandIns.Modules.Remove(module);
                BrovVulkApi.vkDestroyShaderModule(device, module, IntPtr.Zero);
            }

            st.StandIns.TemporaryModules.Clear();
        }

        internal static void DestroyPipeline(GenState st, IntPtr device, IntPtr pipeline) => FillModeNonSolid.DestroyPipeline(st.StandIns, device, pipeline);

        internal static int CreateImage(GenState st, IntPtr device, IntPtr createInfo)
        {
            if (createInfo == IntPtr.Zero || (st.DeviceStandIns(device) & TextureCompressionBcBit) == 0)
                return 0;

            return TextureCompressionBC.CreateImage(st, device, createInfo);
        }

        internal static void NoteImage(GenState st, IntPtr image) => TextureCompressionBC.NoteImage(st.StandIns, image);

        internal static void DestroyImage(GenState st, IntPtr device, IntPtr image)
        {
            if (st.StandIns.CompressionActive)
                TextureCompressionBC.DestroyImage(st.StandIns, device, image);
        }

        internal static int CreateImageView(GenState st, IntPtr device, IntPtr createInfo)
        {
            if (createInfo == IntPtr.Zero || (st.DeviceStandIns(device) & TextureCompressionBcBit) == 0)
                return 0;

            return TextureCompressionBC.CreateImageView(st, createInfo);
        }

        internal static void CreateBuffer(GenState st, IntPtr device, IntPtr createInfo)
        {
            if (createInfo == IntPtr.Zero)
                return;

            int bits = st.DeviceStandIns(device);
            if ((bits & Maintenance5Bit) != 0)
                Maintenance5.FoldBufferUsage(createInfo);
            if ((bits & TextureCompressionBcBit) != 0)
                TextureCompressionBC.CreateBuffer(createInfo);
        }

        internal static void CreateBufferView(GenState st, IntPtr device, IntPtr createInfo)
        {
            if (createInfo != IntPtr.Zero && (st.DeviceStandIns(device) & Maintenance5Bit) != 0)
                Maintenance5.UnlinkBufferViewUsage(createInfo);
        }

        internal static void CreateSampler(GenState st, IntPtr device, IntPtr createInfo)
        {
            if (createInfo == IntPtr.Zero || (st.DeviceStandIns(device) & SamplerAnisotropyBit) == 0)
                return;

            *(uint*)(createInfo + SamplerAnisotropyEnable) = 0;
            *(float*)(createInfo + SamplerMaxAnisotropy) = 1f;
        }

        internal static void CreateRenderPass(GenState st, IntPtr device, IntPtr createInfo, bool version2)
        {
            if (createInfo != IntPtr.Zero && (st.DeviceStandIns(device) & LoadStoreOpNoneBit) != 0)
                LoadStoreOpNone.RenderPass(createInfo, version2);
        }

        internal static bool ImageSubresourceLayout2(GenState st, IntPtr device, IntPtr image, IntPtr subresource, IntPtr layout)
        {
            return (st.DeviceStandIns(device) & Maintenance5Bit) != 0 && Maintenance5.ImageSubresourceLayout2(device, image, subresource, layout);
        }

        internal static bool DeviceImageSubresourceLayout(GenState st, IntPtr device, IntPtr info, IntPtr layout)
        {
            return (st.DeviceStandIns(device) & Maintenance5Bit) != 0 && Maintenance5.DeviceImageSubresourceLayout(device, info, layout);
        }

        internal static bool RenderingAreaGranularity(GenState st, IntPtr device, IntPtr granularity)
        {
            return (st.DeviceStandIns(device) & Maintenance5Bit) != 0 && Maintenance5.RenderingAreaGranularity(granularity);
        }

        internal static bool TranslateBindDescriptorSets2(GenState st, IntPtr commandBuffer, IntPtr info)
        {
            return info != IntPtr.Zero && (st.CommandBufferStandIns(commandBuffer) & Maintenance6Bit) != 0 && Maintenance6.BindDescriptorSets(commandBuffer, info);
        }

        internal static bool TranslatePushConstants2(GenState st, IntPtr commandBuffer, IntPtr info)
        {
            return info != IntPtr.Zero && (st.CommandBufferStandIns(commandBuffer) & Maintenance6Bit) != 0 && Maintenance6.PushConstants(commandBuffer, info);
        }

        internal static bool TranslatePushDescriptorSet2(GenState st, IntPtr commandBuffer, IntPtr info)
        {
            return info != IntPtr.Zero && (st.CommandBufferStandIns(commandBuffer) & Maintenance6Bit) != 0 && Maintenance6.PushDescriptorSet(commandBuffer, info);
        }

        internal static bool TranslateBindDescriptorSets(GenState st, IntPtr commandBuffer, int bindPoint, IntPtr layout, uint firstSet, uint setCount, IntPtr sets, uint offsetCount, IntPtr offsets)
        {
            return (st.CommandBufferStandIns(commandBuffer) & Maintenance6Bit) != 0
                && Maintenance6.HasNullSet(setCount, sets)
                && Maintenance6.BindRuns(commandBuffer, bindPoint, layout, firstSet, setCount, sets, offsetCount, offsets);
        }

        // A null index buffer reads zero at every index, so the substitute is read from its start.
        internal static IntPtr IndexBuffer(GenState st, IntPtr commandBuffer, IntPtr buffer, ref ulong offset)
        {
            if (buffer != IntPtr.Zero || !st.StandIns.CommandBuffers.TryGetValue(commandBuffer, out CommandBufferRecord? record) || (record.Bits & Maintenance6Bit) == 0)
                return buffer;

            IntPtr substitute = Maintenance6.NullIndexBuffer(st.StandIns, st, record.Device);
            if (substitute != IntPtr.Zero)
                offset = 0;

            return substitute;
        }

        internal static bool BindIndexBuffer2(GenState st, IntPtr commandBuffer, IntPtr buffer, ulong offset, int indexType)
        {
            if ((st.CommandBufferStandIns(commandBuffer) & Maintenance5Bit) == 0)
                return false;

            BrovVulkApi.vkCmdBindIndexBuffer(commandBuffer, buffer, offset, indexType);
            return true;
        }

        internal static void VertexBufferSizes(GenState st, IntPtr commandBuffer, uint count, IntPtr buffers, IntPtr offsets, IntPtr sizes)
        {
            if (sizes != IntPtr.Zero && buffers != IntPtr.Zero && (st.CommandBufferStandIns(commandBuffer) & Maintenance5Bit) != 0)
                Maintenance5.VertexBufferSizes(st, count, buffers, offsets, sizes);
        }

        internal static void BeginRendering(GenState st, IntPtr commandBuffer, IntPtr info)
        {
            if (info != IntPtr.Zero && (st.CommandBufferStandIns(commandBuffer) & LoadStoreOpNoneBit) != 0)
                LoadStoreOpNone.BeginRendering(info);
        }

        internal static bool DrawIndirect(GenState st, IntPtr commandBuffer, IntPtr buffer, ulong offset, uint drawCount, uint stride, int kind)
        {
            if (drawCount <= 1 || (st.CommandBufferStandIns(commandBuffer) & MultiDrawIndirectBit) == 0)
                return false;

            uint count = Math.Min(drawCount, MaxStandInDrawCount);
            if (count != drawCount)
                Utils.LogError($"[VulkanImpls] multiDrawIndirect: {drawCount} draws clamped to {MaxStandInDrawCount}.");

            for (uint i = 0; i < count; i++)
            {
                ulong at = offset + (ulong)i * stride;
                switch (kind)
                {
                    case IndirectKindIndexed: BrovVulkApi.vkCmdDrawIndexedIndirect(commandBuffer, buffer, at, 1, stride); break;
                    case IndirectKindMeshExt: BrovVulkApi.vkCmdDrawMeshTasksIndirectEXT(commandBuffer, buffer, at, 1, stride); break;
                    case IndirectKindMeshNv: BrovVulkApi.vkCmdDrawMeshTasksIndirectNV(commandBuffer, buffer, at, 1, stride); break;
                    default: BrovVulkApi.vkCmdDrawIndirect(commandBuffer, buffer, at, 1, stride); break;
                }
            }

            return true;
        }

        // The count lives in device memory, so the host draws whatever the buffer holds up to this bound.
        internal static uint IndirectDrawCount(GenState st, IntPtr commandBuffer, uint maxDrawCount)
        {
            if (maxDrawCount <= 1 || (st.CommandBufferStandIns(commandBuffer) & MultiDrawIndirectBit) == 0)
                return maxDrawCount;

            Utils.LogError("[VulkanImpls] multiDrawIndirect: an indirect count draw is bounded to one draw.");
            return 1;
        }

        internal static int SetPolygonMode(GenState st, IntPtr commandBuffer, int polygonMode)
        {
            if (polygonMode == PolygonModeFill || (st.CommandBufferStandIns(commandBuffer) & FillModeNonSolidBit) == 0)
                return polygonMode;

            Utils.LogError("[VulkanImpls] fillModeNonSolid: a dynamic polygon mode falls back to fill.");
            return PolygonModeFill;
        }

        internal static bool CopyBufferToImage(GenState st, IntPtr commandBuffer, IntPtr buffer, IntPtr image, int layout, uint count, IntPtr regions)
        {
            return st.StandIns.CompressionActive && TextureCompressionBC.CopyBufferToImage(st, commandBuffer, buffer, image, layout, count, regions, false);
        }

        internal static bool CopyBufferToImage2(GenState st, IntPtr commandBuffer, IntPtr info)
        {
            return st.StandIns.CompressionActive && info != IntPtr.Zero && TextureCompressionBC.CopyBufferToImage2(st, commandBuffer, info);
        }

        internal static bool CopyImageToBuffer(GenState st, IntPtr image)
        {
            return st.StandIns.CompressionActive && TextureCompressionBC.RefuseReadback(st.StandIns, image);
        }

        internal static bool CopyImageToBuffer2(GenState st, IntPtr info)
        {
            return st.StandIns.CompressionActive && info != IntPtr.Zero && TextureCompressionBC.RefuseReadback(st.StandIns, *(IntPtr*)(info + VkOffsets.CopyImageToBufferSource));
        }

        internal static bool CopyImage(GenState st, IntPtr source, IntPtr destination)
        {
            return st.StandIns.CompressionActive && TextureCompressionBC.RefuseMismatchedCopy(st.StandIns, source, destination);
        }

        internal static bool CopyImage2(GenState st, IntPtr info)
        {
            return st.StandIns.CompressionActive && info != IntPtr.Zero
                && TextureCompressionBC.RefuseMismatchedCopy(st.StandIns, *(IntPtr*)(info + VkOffsets.CopyImageSource), *(IntPtr*)(info + VkOffsets.CopyImageDestination));
        }

        internal static void NoteCommandPool(GenState st, IntPtr device, IntPtr createInfo, IntPtr pool)
        {
            if (pool == IntPtr.Zero || st.DeviceStandIns(device) == 0)
                return;

            uint family = createInfo != IntPtr.Zero ? *(uint*)(createInfo + CommandPoolQueueFamily) : 0;
            st.StandIns.CommandPools[pool] = new CommandPoolRecord { Device = device, QueueFamily = family };
        }

        internal static void DestroyCommandPool(GenState st, IntPtr pool)
        {
            if (!st.StandIns.CommandPools.Remove(pool, out CommandPoolRecord? record))
                return;

            foreach (IntPtr commandBuffer in record.Buffers)
                ForgetCommandBuffer(st.StandIns, commandBuffer, false);
        }

        internal static void ResetCommandPool(GenState st, IntPtr pool)
        {
            if (!st.StandIns.CommandPools.TryGetValue(pool, out CommandPoolRecord? record))
                return;

            foreach (IntPtr commandBuffer in record.Buffers)
                ResetCommandBuffer(st, commandBuffer);
        }

        internal static void NoteCommandBuffers(GenState st, IntPtr device, IntPtr allocateInfo, uint count, IntPtr commandBuffers)
        {
            int bits = st.DeviceStandIns(device);
            if (bits == 0 || commandBuffers == IntPtr.Zero)
                return;

            IntPtr pool = allocateInfo != IntPtr.Zero ? *(IntPtr*)(allocateInfo + CommandBufferAllocatePool) : IntPtr.Zero;
            st.StandIns.CommandPools.TryGetValue(pool, out CommandPoolRecord? poolRecord);
            for (uint k = 0; k < count; k++)
            {
                IntPtr commandBuffer = Marshal.ReadIntPtr(commandBuffers, (int)k * 8);
                if (commandBuffer == IntPtr.Zero)
                    continue;

                st.StandIns.CommandBuffers[commandBuffer] = new CommandBufferRecord { Device = device, Pool = pool, Bits = bits };
                poolRecord?.Buffers.Add(commandBuffer);
            }
        }

        internal static void ForgetCommandBuffers(GenState st, uint count, IntPtr commandBuffers)
        {
            if (commandBuffers == IntPtr.Zero || st.StandIns.CommandBuffers.Count == 0)
                return;

            for (uint k = 0; k < count; k++)
                ForgetCommandBuffer(st.StandIns, Marshal.ReadIntPtr(commandBuffers, (int)k * 8), true);
        }

        private static void ForgetCommandBuffer(VulkanStandInState state, IntPtr commandBuffer, bool detachFromPool)
        {
            if (!state.CommandBuffers.Remove(commandBuffer, out CommandBufferRecord? record))
                return;

            TextureCompressionBC.ReleaseCommandBuffer(record);
            if (detachFromPool && state.CommandPools.TryGetValue(record.Pool, out CommandPoolRecord? pool))
                pool.Buffers.Remove(commandBuffer);
        }

        internal static void ResetCommandBuffer(GenState st, IntPtr commandBuffer)
        {
            if (!st.StandIns.CommandBuffers.TryGetValue(commandBuffer, out CommandBufferRecord? record))
                return;

            record.Bound = IntPtr.Zero;
            record.BoundWireframe = false;
            record.Topology = -1;
            TextureCompressionBC.ResetCommandBuffer(record);
        }

        internal static IntPtr BindPipeline(GenState st, IntPtr commandBuffer, int bindPoint, IntPtr pipeline)
        {
            if (bindPoint == PipelineBindPointCompute)
            {
                if (st.StandIns.CompressionActive && st.StandIns.CommandBuffers.TryGetValue(commandBuffer, out CommandBufferRecord? record))
                    TextureCompressionBC.NoteComputePipeline(record, pipeline);
                return pipeline;
            }

            return st.StandIns.WireframeActive ? FillModeNonSolid.Bind(st.StandIns, commandBuffer, bindPoint, pipeline) : pipeline;
        }

        internal static void BindDescriptorSets(GenState st, IntPtr commandBuffer, int bindPoint, IntPtr layout, uint firstSet, uint count, IntPtr sets, uint dynamicCount, IntPtr dynamicOffsets)
        {
            if (bindPoint == PipelineBindPointCompute && st.StandIns.CompressionActive && st.StandIns.CommandBuffers.TryGetValue(commandBuffer, out CommandBufferRecord? record))
                TextureCompressionBC.NoteDescriptorSets(record, layout, firstSet, count, sets, dynamicCount, dynamicOffsets);
        }

        internal static void BindDescriptorSets2(GenState st, IntPtr commandBuffer, IntPtr info)
        {
            if (info != IntPtr.Zero && st.StandIns.CompressionActive && st.StandIns.CommandBuffers.TryGetValue(commandBuffer, out CommandBufferRecord? record))
                TextureCompressionBC.NoteDescriptorSets2(record, info);
        }

        internal static void PushConstants(GenState st, IntPtr commandBuffer, IntPtr layout, uint stages, uint offset, uint size, IntPtr values)
        {
            if (st.StandIns.CompressionActive && st.StandIns.CommandBuffers.TryGetValue(commandBuffer, out CommandBufferRecord? record))
                TextureCompressionBC.NotePushConstants(record, layout, stages, offset, size, values);
        }

        internal static void PushConstants2(GenState st, IntPtr commandBuffer, IntPtr info)
        {
            if (info != IntPtr.Zero && st.StandIns.CompressionActive && st.StandIns.CommandBuffers.TryGetValue(commandBuffer, out CommandBufferRecord? record))
                TextureCompressionBC.NotePushConstants2(record, info);
        }

        internal static void SetPrimitiveTopology(GenState st, IntPtr commandBuffer, int topology)
        {
            if (st.StandIns.WireframeActive)
                FillModeNonSolid.SetTopology(st.StandIns, commandBuffer, topology);
        }

        internal static uint BeginQueryFlags(GenState st, IntPtr commandBuffer, uint flags)
        {
            if ((flags & QueryControlPrecise) != 0 && (st.CommandBufferStandIns(commandBuffer) & OcclusionQueryPreciseBit) != 0)
                flags &= ~QueryControlPrecise;
            return flags;
        }

        internal static void ReleaseDevice(GenState st, IntPtr device)
        {
            if (device == IntPtr.Zero ? !st.Retire.Active : !st.Retire.IsCpu(device))
                ReleaseHostDevice(st, device);
        }

        internal static void ReleaseHostDevice(GenState st, IntPtr device)
        {
            VulkanStandInState state = st.StandIns;
            FillModeNonSolid.ReleaseDevice(state, device);
            TextureCompressionBC.ReleaseDevice(state, device);
            Maintenance6.ReleaseDevice(state, device);

            List<IntPtr> gone = new List<IntPtr>();
            foreach (KeyValuePair<IntPtr, CommandBufferRecord> entry in state.CommandBuffers)
            {
                if (device == IntPtr.Zero || entry.Value.Device == device)
                    gone.Add(entry.Key);
            }

            foreach (IntPtr key in gone)
                ForgetCommandBuffer(state, key, false);

            gone.Clear();
            foreach (KeyValuePair<IntPtr, CommandPoolRecord> entry in state.CommandPools)
            {
                if (device == IntPtr.Zero || entry.Value.Device == device)
                    gone.Add(entry.Key);
            }

            foreach (IntPtr key in gone)
                state.CommandPools.Remove(key);
        }
    }

    internal sealed class VulkanStandInState
    {
        public bool WireframeActive;
        public bool ClipActive;
        public bool CompressionActive;
        public readonly Dictionary<IntPtr, ShaderModuleRecord> Modules = new Dictionary<IntPtr, ShaderModuleRecord>();
        public readonly Dictionary<IntPtr, FillModeNonSolid.PipelineRecord> Pipelines = new Dictionary<IntPtr, FillModeNonSolid.PipelineRecord>();
        public readonly Dictionary<IntPtr, CommandBufferRecord> CommandBuffers = new Dictionary<IntPtr, CommandBufferRecord>();
        public readonly Dictionary<IntPtr, CommandPoolRecord> CommandPools = new Dictionary<IntPtr, CommandPoolRecord>();
        public readonly Dictionary<IntPtr, TextureCompressionBC.ImageRecord> Images = new Dictionary<IntPtr, TextureCompressionBC.ImageRecord>();
        public readonly Dictionary<IntPtr, TextureCompressionBC.DeviceRecord> Decoders = new Dictionary<IntPtr, TextureCompressionBC.DeviceRecord>();
        public readonly Dictionary<IntPtr, Maintenance6.NullIndexRecord> NullIndexBuffers = new Dictionary<IntPtr, Maintenance6.NullIndexRecord>();
        public readonly List<FillModeNonSolid.Plan> Plans = new List<FillModeNonSolid.Plan>();
        public readonly List<IntPtr> TemporaryModules = new List<IntPtr>();
        public TextureCompressionBC.ImageRecord? PendingImage;
        public SpirvModuleInfo PendingModule;
    }

    internal sealed class ShaderModuleRecord
    {
        public IntPtr Device;
        public uint Models;
        public int ClipOutputs;
        public uint InterfaceModel;
        public SpirvInterface? Interface;
        public uint[]? Code;
    }

    internal sealed class CommandBufferRecord
    {
        public IntPtr Device;
        public IntPtr Pool;
        public int Bits;
        public IntPtr Bound;
        public bool BoundWireframe;
        public int Topology = -1;
        public TextureCompressionBC.DecodeState? Decode;
    }

    internal sealed class CommandPoolRecord
    {
        public IntPtr Device;
        public uint QueueFamily;
        public readonly List<IntPtr> Buffers = new List<IntPtr>();
    }

    internal static class VkOffsets
    {
        internal static readonly int NodePNext = BrovVulkLayout.MemberOffset["VkBaseOutStructure.pNext"];

        internal static readonly int ShaderModuleCodeSize = BrovVulkLayout.MemberOffset["VkShaderModuleCreateInfo.codeSize"];
        internal static readonly int ShaderModuleCode = BrovVulkLayout.MemberOffset["VkShaderModuleCreateInfo.pCode"];
        internal static readonly int ShaderModuleSize = BrovVulkLayout.StructSize["VkShaderModuleCreateInfo"];

        internal static readonly int StageSize = BrovVulkLayout.StructSize["VkPipelineShaderStageCreateInfo"];
        internal static readonly int StagePNext = BrovVulkLayout.MemberOffset["VkPipelineShaderStageCreateInfo.pNext"];
        internal static readonly int StageStage = BrovVulkLayout.MemberOffset["VkPipelineShaderStageCreateInfo.stage"];
        internal static readonly int StageModule = BrovVulkLayout.MemberOffset["VkPipelineShaderStageCreateInfo.module"];
        internal static readonly int StageName = BrovVulkLayout.MemberOffset["VkPipelineShaderStageCreateInfo.pName"];

        internal static readonly int PipelineSize = BrovVulkLayout.StructSize["VkGraphicsPipelineCreateInfo"];
        internal static readonly int PipelinePNext = BrovVulkLayout.MemberOffset["VkGraphicsPipelineCreateInfo.pNext"];
        internal static readonly int PipelineFlags = BrovVulkLayout.MemberOffset["VkGraphicsPipelineCreateInfo.flags"];
        internal static readonly int PipelineStageCount = BrovVulkLayout.MemberOffset["VkGraphicsPipelineCreateInfo.stageCount"];
        internal static readonly int PipelineStages = BrovVulkLayout.MemberOffset["VkGraphicsPipelineCreateInfo.pStages"];
        internal static readonly int PipelineInputAssembly = BrovVulkLayout.MemberOffset["VkGraphicsPipelineCreateInfo.pInputAssemblyState"];
        internal static readonly int PipelineViewport = BrovVulkLayout.MemberOffset["VkGraphicsPipelineCreateInfo.pViewportState"];
        internal static readonly int PipelineRasterization = BrovVulkLayout.MemberOffset["VkGraphicsPipelineCreateInfo.pRasterizationState"];
        internal static readonly int PipelineDynamicState = BrovVulkLayout.MemberOffset["VkGraphicsPipelineCreateInfo.pDynamicState"];
        internal static readonly int PipelineBaseHandle = BrovVulkLayout.MemberOffset["VkGraphicsPipelineCreateInfo.basePipelineHandle"];
        internal static readonly int PipelineBaseIndex = BrovVulkLayout.MemberOffset["VkGraphicsPipelineCreateInfo.basePipelineIndex"];
        internal static readonly int ComputePipelineFlags = BrovVulkLayout.MemberOffset["VkComputePipelineCreateInfo.flags"];
        internal static readonly int ComputePipelineStage = BrovVulkLayout.MemberOffset["VkComputePipelineCreateInfo.stage"];
        internal static readonly int ComputePipelineLayout = BrovVulkLayout.MemberOffset["VkComputePipelineCreateInfo.layout"];
        internal static readonly int PipelineLayout = BrovVulkLayout.MemberOffset["VkGraphicsPipelineCreateInfo.layout"];
        internal static readonly int CreateFlags2 = BrovVulkLayout.MemberOffset["VkPipelineCreateFlags2CreateInfo.flags"];

        internal static readonly int InputAssemblyTopology = BrovVulkLayout.MemberOffset["VkPipelineInputAssemblyStateCreateInfo.topology"];
        internal static readonly int RasterizationDiscard = BrovVulkLayout.MemberOffset["VkPipelineRasterizationStateCreateInfo.rasterizerDiscardEnable"];
        internal static readonly int RasterizationPolygonMode = BrovVulkLayout.MemberOffset["VkPipelineRasterizationStateCreateInfo.polygonMode"];
        internal static readonly int DynamicStateCount = BrovVulkLayout.MemberOffset["VkPipelineDynamicStateCreateInfo.dynamicStateCount"];
        internal static readonly int DynamicStates = BrovVulkLayout.MemberOffset["VkPipelineDynamicStateCreateInfo.pDynamicStates"];
        internal static readonly int ViewportCount = BrovVulkLayout.MemberOffset["VkPipelineViewportStateCreateInfo.viewportCount"];
        internal static readonly int ScissorCount = BrovVulkLayout.MemberOffset["VkPipelineViewportStateCreateInfo.scissorCount"];

        internal static readonly int LibraryCount = BrovVulkLayout.MemberOffset["VkPipelineLibraryCreateInfoKHR.libraryCount"];
        internal static readonly int LibraryHandles = BrovVulkLayout.MemberOffset["VkPipelineLibraryCreateInfoKHR.pLibraries"];
        internal static readonly int LibraryFlags = BrovVulkLayout.MemberOffset["VkGraphicsPipelineLibraryCreateInfoEXT.flags"];

        internal static readonly int ImageFlags = BrovVulkLayout.MemberOffset["VkImageCreateInfo.flags"];
        internal static readonly int ImageType = BrovVulkLayout.MemberOffset["VkImageCreateInfo.imageType"];
        internal static readonly int ImageFormat = BrovVulkLayout.MemberOffset["VkImageCreateInfo.format"];
        internal static readonly int ImageWidth = BrovVulkLayout.MemberOffset["VkImageCreateInfo.extent"] + BrovVulkLayout.MemberOffset["VkExtent3D.width"];
        internal static readonly int ImageHeight = BrovVulkLayout.MemberOffset["VkImageCreateInfo.extent"] + BrovVulkLayout.MemberOffset["VkExtent3D.height"];
        internal static readonly int ImageDepth = BrovVulkLayout.MemberOffset["VkImageCreateInfo.extent"] + BrovVulkLayout.MemberOffset["VkExtent3D.depth"];
        internal static readonly int ImageMipLevels = BrovVulkLayout.MemberOffset["VkImageCreateInfo.mipLevels"];
        internal static readonly int ImageTiling = BrovVulkLayout.MemberOffset["VkImageCreateInfo.tiling"];
        internal static readonly int ImageUsage = BrovVulkLayout.MemberOffset["VkImageCreateInfo.usage"];

        internal static readonly int ImageFormatInfoFormat = BrovVulkLayout.MemberOffset["VkPhysicalDeviceImageFormatInfo2.format"];
        internal static readonly int CopyImageSource = BrovVulkLayout.MemberOffset["VkCopyImageInfo2.srcImage"];
        internal static readonly int CopyImageDestination = BrovVulkLayout.MemberOffset["VkCopyImageInfo2.dstImage"];
        internal static readonly int CopyImageToBufferSource = BrovVulkLayout.MemberOffset["VkCopyImageToBufferInfo2.srcImage"];
    }
}
