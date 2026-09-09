using System;
using System.Collections.Generic;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// Stands in for VK_KHR_maintenance5. The flag structs fold into the plain flags, inline shader code
    /// becomes a module for the pipeline call, the new queries and the sized index bind map to their Vulkan
    /// 1.0 forms, and the two new formats are reported as unsupported.
    /// </summary>
    internal static unsafe class Maintenance5
    {
        private const uint StShaderModuleCreateInfo = 16;
        private const uint StPipelineCreateFlags2CreateInfo = 1000470005;
        private const uint StBufferUsageFlags2CreateInfo = 1000470006;
        private const int FormatA1B5G5R5UnormPack16 = 1000470000;
        private const int FormatA8Unorm = 1000470001;
        private const ulong WholeSize = ulong.MaxValue;

        private static readonly HashSet<string> Reported = new HashSet<string>(StringComparer.Ordinal);

        private static class L
        {
            internal static readonly int CreateFlags2 = BrovVulkLayout.MemberOffset["VkPipelineCreateFlags2CreateInfo.flags"];
            internal static readonly int BufferUsage = BrovVulkLayout.MemberOffset["VkBufferCreateInfo.usage"];
            internal static readonly int BufferUsage2 = BrovVulkLayout.MemberOffset["VkBufferUsageFlags2CreateInfo.usage"];
            internal static readonly int Subresource2Subresource = BrovVulkLayout.MemberOffset["VkImageSubresource2.imageSubresource"];
            internal static readonly int Layout2Layout = BrovVulkLayout.MemberOffset["VkSubresourceLayout2.subresourceLayout"];
            internal static readonly int SubresourceInfoCreateInfo = BrovVulkLayout.MemberOffset["VkDeviceImageSubresourceInfo.pCreateInfo"];
            internal static readonly int SubresourceInfoSubresource = BrovVulkLayout.MemberOffset["VkDeviceImageSubresourceInfo.pSubresource"];
        }

        private static void Complain(string reason)
        {
            if (Reported.Add(reason))
                Utils.LogError("[VulkanImpls] VK_KHR_maintenance5: " + reason + ".");
        }

        internal static bool IsNewFormat(int format) => format == FormatA1B5G5R5UnormPack16 || format == FormatA8Unorm;

        // The low word of VkPipelineCreateFlags2 is VkPipelineCreateFlags, and the struct replaces the plain flags.
        internal static void FoldCreateFlags(IntPtr info, int flagsOffset)
        {
            IntPtr* link = (IntPtr*)(info + VkOffsets.NodePNext);
            while (*link != IntPtr.Zero)
            {
                IntPtr node = *link;
                if (*(uint*)node != StPipelineCreateFlags2CreateInfo)
                {
                    link = (IntPtr*)(node + VkOffsets.NodePNext);
                    continue;
                }

                ulong flags = *(ulong*)(node + L.CreateFlags2);
                if ((flags >> 32) != 0)
                    Complain("a pipeline uses create flags above bit 31, which the host cannot take");
                *(uint*)(info + flagsOffset) = (uint)flags;
                *link = *(IntPtr*)(node + VkOffsets.NodePNext);
            }
        }

        internal static void FoldBufferUsage(IntPtr createInfo)
        {
            IntPtr* link = (IntPtr*)(createInfo + VkOffsets.NodePNext);
            while (*link != IntPtr.Zero)
            {
                IntPtr node = *link;
                if (*(uint*)node != StBufferUsageFlags2CreateInfo)
                {
                    link = (IntPtr*)(node + VkOffsets.NodePNext);
                    continue;
                }

                ulong usage = *(ulong*)(node + L.BufferUsage2);
                if ((usage >> 32) != 0)
                    Complain("a buffer uses usage flags above bit 31, which the host cannot take");
                *(uint*)(createInfo + L.BufferUsage) = (uint)usage;
                *link = *(IntPtr*)(node + VkOffsets.NodePNext);
            }
        }

        // A view without the struct takes every usage of its buffer, a superset of what was asked.
        internal static void UnlinkBufferViewUsage(IntPtr createInfo)
        {
            IntPtr* link = (IntPtr*)(createInfo + VkOffsets.NodePNext);
            while (*link != IntPtr.Zero)
            {
                IntPtr node = *link;
                if (*(uint*)node == StBufferUsageFlags2CreateInfo)
                    *link = *(IntPtr*)(node + VkOffsets.NodePNext);
                else
                    link = (IntPtr*)(node + VkOffsets.NodePNext);
            }
        }

        // The modules live in VulkanStandInState.TemporaryModules until the pipeline call returns.
        internal static void MaterializeModules(GenState st, IntPtr device, IntPtr stages, uint count)
        {
            if (stages == IntPtr.Zero)
                return;

            for (uint i = 0; i < count; i++)
            {
                IntPtr stage = stages + (int)(i * (uint)VkOffsets.StageSize);
                if (*(IntPtr*)(stage + VkOffsets.StageModule) != IntPtr.Zero)
                    continue;

                IntPtr* link = (IntPtr*)(stage + VkOffsets.StagePNext);
                while (*link != IntPtr.Zero)
                {
                    IntPtr node = *link;
                    if (*(uint*)node != StShaderModuleCreateInfo)
                    {
                        link = (IntPtr*)(node + VkOffsets.NodePNext);
                        continue;
                    }

                    IntPtr next = *(IntPtr*)(node + VkOffsets.NodePNext);
                    IntPtr module = ModuleFor(st, device, node);
                    if (module != IntPtr.Zero)
                    {
                        *(IntPtr*)(stage + VkOffsets.StageModule) = module;
                        *link = next;
                    }

                    break;
                }
            }
        }

        // The stage chain behind the inline node is not a module chain, so the node is created on its own.
        private static IntPtr ModuleFor(GenState st, IntPtr device, IntPtr node)
        {
            IntPtr next = *(IntPtr*)(node + VkOffsets.NodePNext);
            *(IntPtr*)(node + VkOffsets.NodePNext) = IntPtr.Zero;
            VulkanStandIns.PatchShaderModule(st, device, node);
            IntPtr module = IntPtr.Zero;
            int result = BrovVulkApi.vkCreateShaderModule(device, node, IntPtr.Zero, (IntPtr)(&module));
            if (result >= 0 && module != IntPtr.Zero)
                VulkanStandIns.NoteShaderModule(st, device, node, module);
            *(IntPtr*)(node + VkOffsets.NodePNext) = next;
            if (result < 0 || module == IntPtr.Zero)
            {
                Complain("a shader module could not be made from inline pipeline code");
                return IntPtr.Zero;
            }

            st.StandIns.TemporaryModules.Add(module);
            return module;
        }

        internal static void VertexBufferSizes(GenState st, uint count, IntPtr buffers, IntPtr offsets, IntPtr sizes)
        {
            for (uint i = 0; i < count; i++)
            {
                ulong* size = (ulong*)(sizes + (int)(i * 8));
                if (*size != WholeSize)
                    continue;

                ulong total = st.BufferSize(*(IntPtr*)(buffers + (int)(i * 8)));
                ulong offset = offsets != IntPtr.Zero ? *(ulong*)(offsets + (int)(i * 8)) : 0;
                *size = total > offset ? total - offset : 0;
            }
        }

        internal static bool ImageSubresourceLayout2(IntPtr device, IntPtr image, IntPtr subresource, IntPtr layout)
        {
            if (subresource == IntPtr.Zero || layout == IntPtr.Zero)
                return false;

            BrovVulkApi.vkGetImageSubresourceLayout(device, image, subresource + L.Subresource2Subresource, layout + L.Layout2Layout);
            return true;
        }

        internal static bool DeviceImageSubresourceLayout(IntPtr device, IntPtr info, IntPtr layout)
        {
            if (info == IntPtr.Zero || layout == IntPtr.Zero)
                return false;

            IntPtr createInfo = *(IntPtr*)(info + L.SubresourceInfoCreateInfo);
            IntPtr subresource = *(IntPtr*)(info + L.SubresourceInfoSubresource);
            if (createInfo == IntPtr.Zero || subresource == IntPtr.Zero)
                return true;

            IntPtr image = IntPtr.Zero;
            if (BrovVulkApi.vkCreateImage(device, createInfo, IntPtr.Zero, (IntPtr)(&image)) < 0 || image == IntPtr.Zero)
            {
                Complain("the image for a subresource layout query could not be created, the layout reads as zero");
                return true;
            }

            BrovVulkApi.vkGetImageSubresourceLayout(device, image, subresource + L.Subresource2Subresource, layout + L.Layout2Layout);
            BrovVulkApi.vkDestroyImage(device, image, IntPtr.Zero);
            return true;
        }

        internal static bool RenderingAreaGranularity(IntPtr granularity)
        {
            if (granularity == IntPtr.Zero)
                return false;

            *(uint*)granularity = 1;
            *(uint*)(granularity + 4) = 1;
            return true;
        }
    }
}
