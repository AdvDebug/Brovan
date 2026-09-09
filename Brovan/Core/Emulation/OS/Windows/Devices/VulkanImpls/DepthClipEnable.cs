using System;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// Stands in for VK_EXT_depth_clip_enable. Without the extension a pipeline clips depth exactly when it
    /// does not clamp it.
    /// </summary>
    internal static unsafe class DepthClipEnable
    {
        private const uint StPipelineRasterizationDepthClipStateCreateInfoExt = 1000102001;

        private static readonly int DepthClampEnable = BrovVulkLayout.MemberOffset["VkPipelineRasterizationStateCreateInfo.depthClampEnable"];
        private static readonly int DepthClipEnableField = BrovVulkLayout.MemberOffset["VkPipelineRasterizationDepthClipStateCreateInfoEXT.depthClipEnable"];

        internal static void PatchPipeline(IntPtr info)
        {
            IntPtr rasterization = *(IntPtr*)(info + VkOffsets.PipelineRasterization);
            if (rasterization == IntPtr.Zero)
                return;

            IntPtr* link = (IntPtr*)(rasterization + VkOffsets.NodePNext);
            while (*link != IntPtr.Zero)
            {
                IntPtr node = *link;
                if (*(uint*)node != StPipelineRasterizationDepthClipStateCreateInfoExt)
                {
                    link = (IntPtr*)(node + VkOffsets.NodePNext);
                    continue;
                }

                *(uint*)(rasterization + DepthClampEnable) = *(uint*)(node + DepthClipEnableField) != 0 ? 0u : 1u;
                *link = *(IntPtr*)(node + VkOffsets.NodePNext);
            }
        }
    }
}
