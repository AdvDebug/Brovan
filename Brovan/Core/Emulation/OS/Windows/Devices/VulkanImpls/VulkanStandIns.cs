using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Brovan.Core.Helpers;

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

        internal const int HostGeometryShaderBit = 1 << 8;
        internal const int HostGeometryPointSizeBit = 1 << 9;
        internal const int HostClipDistanceBit = 1 << 10;
        internal const int HostCullDistanceBit = 1 << 11;

        private const int RelocationBits = MultiViewportBit | ClipDistanceBit | CullDistanceBit;

        private const string FeaturePrefix = "VkPhysicalDeviceFeatures.";

        /// <summary>Comma separated core features to treat as missing, so a capable host runs the stand-ins.</summary>
        private const string ForceVariable = "BROVVULK_FORCE_STANDINS";

        private const uint StPhysicalDeviceFeatures2 = 1000059000u;
        private const uint StPhysicalDeviceTransformFeedbackFeaturesExt = 1000028000u;
        private const uint StPhysicalDeviceRobustness2FeaturesExt = 1000286000u;

        private const int PipelineBindPointCompute = 1;
        private const uint QueryControlPrecise = 1;
        private const uint QueueGraphics = 1;
        private const uint QueueCompute = 2;
        private const uint QueueTransfer = 4;
        private const int MaxLocations = 32;

        private static readonly int DeviceCreateInfoPNext = BrovVulkLayout.MemberOffset["VkDeviceCreateInfo.pNext"];
        private static readonly int DeviceCreateInfoEnabledFeatures = BrovVulkLayout.MemberOffset["VkDeviceCreateInfo.pEnabledFeatures"];

        // Every feature struct shares the VkPhysicalDeviceFeatures2 header.
        private static readonly int FeatureBits = BrovVulkLayout.MemberOffset["VkPhysicalDeviceFeatures2.features"];

        private static readonly int PropertiesLimits = BrovVulkLayout.MemberOffset["VkPhysicalDeviceProperties.limits"];
        private static readonly int LimitsStorageAlignment = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.minStorageBufferOffsetAlignment"];
        private static readonly int LimitsStorageRange = BrovVulkLayout.MemberOffset["VkPhysicalDeviceLimits.maxStorageBufferRange"];
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
        };

        private static readonly (int Bit, string Name)[] HostAbilities =
        {
            (HostGeometryShaderBit, "geometryShader"),
            (HostGeometryPointSizeBit, "shaderTessellationAndGeometryPointSize"),
            (HostClipDistanceBit, "shaderClipDistance"),
            (HostCullDistanceBit, "shaderCullDistance"),
        };

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
            public string[] Missing = Array.Empty<string>();
            public SpirvRelocation Relocation = new SpirvRelocation(-1, -1, -1);
            public uint StorageAlignment = 256;
            public ulong StorageRange = 1 << 27;
            public bool R8Storage;
            public bool Rg8Storage;
            public uint[] QueueFamilies = Array.Empty<uint>();
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
                GapsByDevice[physicalDevice] = gaps;
                return gaps;
            }
        }

        private static void ProbeLimits(IntPtr physicalDevice, DeviceGaps gaps)
        {
            int size = BrovVulkLayout.StructSize["VkPhysicalDeviceProperties"];
            byte* properties = stackalloc byte[size];
            new Span<byte>(properties, size).Clear();
            BrovVulkApi.vkGetPhysicalDeviceProperties(physicalDevice, (IntPtr)properties);
            byte* limits = properties + PropertiesLimits;

            ulong alignment = *(ulong*)(limits + LimitsStorageAlignment);
            if (alignment != 0 && alignment <= 4096 && (alignment & (alignment - 1)) == 0)
                gaps.StorageAlignment = (uint)alignment;
            uint range = *(uint*)(limits + LimitsStorageRange);
            if (range != 0)
                gaps.StorageRange = range;

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

        internal static void Advertise(IntPtr physicalDevice, IntPtr features)
        {
            if (features == IntPtr.Zero)
                return;

            Write(features, Gaps(physicalDevice), 1);
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

            if ((gaps.ImplementedBits & FillModeNonSolidBit) != 0)
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
                    if ((gaps.HostBits & bit) != 0 && (bit == HostGeometryShaderBit || bit == HostGeometryPointSizeBit))
                        *(uint*)((byte*)block + Offset(name)) = 1;
                }
            }

            Report(gaps);
            return bits;
        }

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
            if (!TextureCompressionBC.IsCompressed(format) || !Compression(physicalDevice, out DeviceGaps gaps))
                return 0;

            return TextureCompressionBC.ImageFormatProperties(gaps, ref format, type, tiling, ref usage, ref flags);
        }

        internal static int ImageFormatProperties2(GenState st, IntPtr physicalDevice, IntPtr info)
        {
            if (info == IntPtr.Zero)
                return 0;

            int format = *(int*)(info + VkOffsets.ImageFormatInfoFormat);
            if (!TextureCompressionBC.IsCompressed(format) || !Compression(physicalDevice, out DeviceGaps gaps))
                return 0;

            return TextureCompressionBC.ImageFormatProperties2(st, gaps, info);
        }

        internal static void QueueFamilyProperties(IntPtr physicalDevice, uint count, IntPtr properties, int stride, int flagsOffset)
        {
            if (properties == IntPtr.Zero || !Compression(physicalDevice, out _))
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
            if ((bits & (FillModeNonSolidBit | ClipDistanceBit)) == 0)
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
            if ((bits & (RelocationBits | FillModeNonSolidBit)) == 0 || createInfos == IntPtr.Zero || stride <= 0)
                return;

            for (uint i = 0; i < count; i++)
            {
                IntPtr info = createInfos + (int)(i * (uint)stride);

                if ((bits & RelocationBits) != 0)
                    ShaderPatches.PreparePipeline(st, device, bits, info);

                if ((bits & MultiViewportBit) != 0)
                    MultiViewport.PatchPipeline(info);

                if ((bits & FillModeNonSolidBit) != 0)
                    FillModeNonSolid.PreparePipeline(st.StandIns, st, device, bits, info, (int)i);
            }
        }

        internal static void FinishPipelines(GenState st, IntPtr device, IntPtr cache, IntPtr pipelines, int result)
        {
            if (st.StandIns.Plans.Count != 0 || st.StandIns.TemporaryModules.Count != 0)
                FillModeNonSolid.FinishPipelines(st.StandIns, st, device, cache, pipelines, result);
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
            if (createInfo != IntPtr.Zero && (st.DeviceStandIns(device) & TextureCompressionBcBit) != 0)
                TextureCompressionBC.CreateBuffer(createInfo);
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
            VulkanStandInState state = st.StandIns;
            FillModeNonSolid.ReleaseDevice(state, device);
            TextureCompressionBC.ReleaseDevice(state, device);

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

        internal static readonly int ImageFormatInfoFormat = BrovVulkLayout.MemberOffset["VkPhysicalDeviceImageFormatInfo2.format"];
        internal static readonly int CopyImageSource = BrovVulkLayout.MemberOffset["VkCopyImageInfo2.srcImage"];
        internal static readonly int CopyImageDestination = BrovVulkLayout.MemberOffset["VkCopyImageInfo2.dstImage"];
        internal static readonly int CopyImageToBufferSource = BrovVulkLayout.MemberOffset["VkCopyImageToBufferInfo2.srcImage"];
    }
}
