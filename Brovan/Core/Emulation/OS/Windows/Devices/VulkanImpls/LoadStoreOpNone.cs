using System;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// Stands in for VK_KHR_load_store_op_none. LOAD_OP_NONE keeps the content an attachment already has,
    /// which a load also does at the cost of the read.
    /// </summary>
    internal static unsafe class LoadStoreOpNone
    {
        private const int LoadOpLoad = 0;
        private const int LoadOpNone = 1000400000;

        private static class L
        {
            internal static readonly int ColorCount = BrovVulkLayout.MemberOffset["VkRenderingInfo.colorAttachmentCount"];
            internal static readonly int Colors = BrovVulkLayout.MemberOffset["VkRenderingInfo.pColorAttachments"];
            internal static readonly int Depth = BrovVulkLayout.MemberOffset["VkRenderingInfo.pDepthAttachment"];
            internal static readonly int Stencil = BrovVulkLayout.MemberOffset["VkRenderingInfo.pStencilAttachment"];
            internal static readonly int AttachmentSize = BrovVulkLayout.StructSize["VkRenderingAttachmentInfo"];
            internal static readonly int AttachmentLoadOp = BrovVulkLayout.MemberOffset["VkRenderingAttachmentInfo.loadOp"];

            internal static readonly int PassCount = BrovVulkLayout.MemberOffset["VkRenderPassCreateInfo.attachmentCount"];
            internal static readonly int PassAttachments = BrovVulkLayout.MemberOffset["VkRenderPassCreateInfo.pAttachments"];
            internal static readonly int DescriptionSize = BrovVulkLayout.StructSize["VkAttachmentDescription"];
            internal static readonly int DescriptionLoadOp = BrovVulkLayout.MemberOffset["VkAttachmentDescription.loadOp"];
            internal static readonly int DescriptionStencilLoadOp = BrovVulkLayout.MemberOffset["VkAttachmentDescription.stencilLoadOp"];

            internal static readonly int Pass2Count = BrovVulkLayout.MemberOffset["VkRenderPassCreateInfo2.attachmentCount"];
            internal static readonly int Pass2Attachments = BrovVulkLayout.MemberOffset["VkRenderPassCreateInfo2.pAttachments"];
            internal static readonly int Description2Size = BrovVulkLayout.StructSize["VkAttachmentDescription2"];
            internal static readonly int Description2LoadOp = BrovVulkLayout.MemberOffset["VkAttachmentDescription2.loadOp"];
            internal static readonly int Description2StencilLoadOp = BrovVulkLayout.MemberOffset["VkAttachmentDescription2.stencilLoadOp"];
        }

        internal static void BeginRendering(IntPtr info)
        {
            uint count = *(uint*)(info + L.ColorCount);
            IntPtr colors = *(IntPtr*)(info + L.Colors);
            for (uint i = 0; i < count && colors != IntPtr.Zero; i++)
                Replace(colors + (int)(i * (uint)L.AttachmentSize) + L.AttachmentLoadOp);

            IntPtr depth = *(IntPtr*)(info + L.Depth);
            if (depth != IntPtr.Zero)
                Replace(depth + L.AttachmentLoadOp);

            IntPtr stencil = *(IntPtr*)(info + L.Stencil);
            if (stencil != IntPtr.Zero)
                Replace(stencil + L.AttachmentLoadOp);
        }

        internal static void RenderPass(IntPtr createInfo, bool version2)
        {
            uint count = *(uint*)(createInfo + (version2 ? L.Pass2Count : L.PassCount));
            IntPtr attachments = *(IntPtr*)(createInfo + (version2 ? L.Pass2Attachments : L.PassAttachments));
            int size = version2 ? L.Description2Size : L.DescriptionSize;
            int loadOp = version2 ? L.Description2LoadOp : L.DescriptionLoadOp;
            int stencilLoadOp = version2 ? L.Description2StencilLoadOp : L.DescriptionStencilLoadOp;
            for (uint i = 0; i < count && attachments != IntPtr.Zero; i++)
            {
                IntPtr attachment = attachments + (int)(i * (uint)size);
                Replace(attachment + loadOp);
                Replace(attachment + stencilLoadOp);
            }
        }

        private static void Replace(IntPtr field)
        {
            if (*(int*)field == LoadOpNone)
                *(int*)field = LoadOpLoad;
        }
    }
}
