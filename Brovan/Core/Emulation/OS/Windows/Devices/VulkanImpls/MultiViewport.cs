using System;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// Stands in for multiViewport by keeping the first viewport, which is all a D3D11 guest binds unless a
    /// shader writes SV_ViewportArrayIndex. That write becomes a user output through the shader relocation.
    /// </summary>
    internal static unsafe class MultiViewport
    {
        private static bool Reported;

        internal static void PatchPipeline(IntPtr createInfo)
        {
            IntPtr viewport = *(IntPtr*)(createInfo + VkOffsets.PipelineViewport);
            if (viewport == IntPtr.Zero)
                return;

            uint* viewportCount = (uint*)(viewport + VkOffsets.ViewportCount);
            uint* scissorCount = (uint*)(viewport + VkOffsets.ScissorCount);

            if (*viewportCount <= 1 && *scissorCount <= 1)
                return;

            if (*viewportCount > 1)
                *viewportCount = 1;
            if (*scissorCount > 1)
                *scissorCount = 1;

            Complain();
        }

        internal static uint Clamp(uint count)
        {
            if (count <= 1)
                return count;

            Complain();
            return 1;
        }

        internal static bool Skip(uint first)
        {
            if (first == 0)
                return false;

            Complain();
            return true;
        }

        private static void Complain()
        {
            if (Reported)
                return;

            Reported = true;
            Utils.LogError("[VulkanImpls] multiViewport: the guest bound more than one viewport, only the first is drawn.");
        }
    }
}
