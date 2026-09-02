using System;
using System.Collections.Generic;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// Core Vulkan features presented to the guest when the host driver lacks them.
    /// </summary>
    internal static unsafe class VulkanStandIns
    {
        internal const int MultiViewportBit = 1 << 0;
        internal const int FillModeNonSolidBit = 1 << 1;

        internal const int HostGeometryShaderBit = 1 << 8;
        internal const int HostGeometryPointSizeBit = 1 << 9;
        internal const int HostClipDistanceBit = 1 << 10;
        internal const int HostCullDistanceBit = 1 << 11;

        private const string FeaturePrefix = "VkPhysicalDeviceFeatures.";

        /// <summary>Comma separated core features to treat as missing, so a capable host runs the stand-ins.</summary>
        private const string ForceVariable = "BROVVULK_FORCE_STANDINS";

        private const uint StPhysicalDeviceFeatures2 = 1000059000u;
        private const uint StPhysicalDeviceTransformFeedbackFeaturesExt = 1000028000u;
        private const uint StPhysicalDeviceRobustness2FeaturesExt = 1000286000u;

        private static readonly int DeviceCreateInfoPNext = BrovVulkLayout.MemberOffset["VkDeviceCreateInfo.pNext"];
        private static readonly int DeviceCreateInfoEnabledFeatures = BrovVulkLayout.MemberOffset["VkDeviceCreateInfo.pEnabledFeatures"];

        // Every feature struct shares the VkPhysicalDeviceFeatures2 header.
        private static readonly int FeatureBits = BrovVulkLayout.MemberOffset["VkPhysicalDeviceFeatures2.features"];

        private static readonly (int Bit, string Name)[] Features =
        {
            (MultiViewportBit, "multiViewport"),
            (FillModeNonSolidBit, "fillModeNonSolid"),
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

        private sealed class DeviceGaps
        {
            public int ImplementedBits;
            public int HostBits;
            public string[] Missing = Array.Empty<string>();
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

        /// <summary>Advertise the missing features that have no stand-in.</summary>
        internal static bool Relax;

        private static int Offset(string name) => BrovVulkLayout.MemberOffset[FeaturePrefix + name];

        private static DeviceGaps Gaps(IntPtr physicalDevice)
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

                GapsByDevice[physicalDevice] = gaps;
                return gaps;
            }
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
            bool wireframe = (gaps.ImplementedBits & FillModeNonSolidBit) != 0;
            if (wireframe)
                st.StandIns.WireframeActive = true;
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

            if (wireframe)
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
                byte* supported = stackalloc byte[64];
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

        internal static void PatchShaderModule(GenState st, IntPtr device, IntPtr createInfo)
        {
            if ((st.DeviceStandIns(device) & MultiViewportBit) != 0)
                MultiViewport.PatchShaderModule(createInfo);
        }

        internal static void NoteShaderModule(GenState st, IntPtr device, IntPtr createInfo, IntPtr module)
        {
            if ((st.DeviceStandIns(device) & FillModeNonSolidBit) != 0)
                FillModeNonSolid.NoteShaderModule(st.StandIns, device, createInfo, module);
        }

        internal static void ForgetShaderModule(GenState st, IntPtr module) => st.StandIns.Modules.Remove(module);

        internal static void PreparePipelines(GenState st, IntPtr device, IntPtr createInfos, uint count, int stride)
        {
            int bits = st.DeviceStandIns(device);
            if ((bits & (MultiViewportBit | FillModeNonSolidBit)) == 0 || createInfos == IntPtr.Zero || stride <= 0)
                return;

            for (uint i = 0; i < count; i++)
            {
                IntPtr info = createInfos + (int)(i * (uint)stride);

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

        internal static IntPtr BindPipeline(GenState st, IntPtr commandBuffer, int bindPoint, IntPtr pipeline) => FillModeNonSolid.Bind(st.StandIns, commandBuffer, bindPoint, pipeline);

        internal static void SetPrimitiveTopology(GenState st, IntPtr commandBuffer, int topology) => FillModeNonSolid.SetTopology(st.StandIns, commandBuffer, topology);

        internal static void ResetCommandBuffer(GenState st, IntPtr commandBuffer) => st.StandIns.CommandBuffers.Remove(commandBuffer);

        internal static void ReleaseDevice(GenState st, IntPtr device) => FillModeNonSolid.ReleaseDevice(st.StandIns, device);
    }

    internal sealed class VulkanStandInState
    {
        public bool WireframeActive;
        public readonly Dictionary<IntPtr, FillModeNonSolid.ModuleRecord> Modules = new Dictionary<IntPtr, FillModeNonSolid.ModuleRecord>();
        public readonly Dictionary<IntPtr, FillModeNonSolid.PipelineRecord> Pipelines = new Dictionary<IntPtr, FillModeNonSolid.PipelineRecord>();
        public readonly Dictionary<IntPtr, FillModeNonSolid.CommandBufferRecord> CommandBuffers = new Dictionary<IntPtr, FillModeNonSolid.CommandBufferRecord>();
        public readonly List<FillModeNonSolid.Plan> Plans = new List<FillModeNonSolid.Plan>();
        public readonly List<IntPtr> TemporaryModules = new List<IntPtr>();
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
    }
}
