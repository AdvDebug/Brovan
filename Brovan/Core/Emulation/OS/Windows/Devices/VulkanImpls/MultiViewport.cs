using System;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// Stands in for multiViewport by keeping the first viewport, which is all a D3D11 guest binds unless a
    /// shader writes SV_ViewportArrayIndex. Such writes are removed from the shader so it stays valid.
    /// </summary>
    internal static unsafe class MultiViewport
    {
        private const uint StShaderModuleCreateInfo = 16;

        private static bool Reported;
        private static bool ReportedShader;

        internal static void PatchShaderModule(IntPtr createInfo) => StripCode(createInfo);

        internal static void PatchPipeline(IntPtr createInfo)
        {
            IntPtr stages = *(IntPtr*)(createInfo + VkOffsets.PipelineStages);
            uint stageCount = *(uint*)(createInfo + VkOffsets.PipelineStageCount);
            for (uint i = 0; i < stageCount && stages != IntPtr.Zero; i++)
            {
                IntPtr stage = stages + (int)(i * (uint)VkOffsets.StageSize);
                for (IntPtr node = *(IntPtr*)(stage + VkOffsets.StagePNext); node != IntPtr.Zero; node = *(IntPtr*)(node + VkOffsets.NodePNext))
                {
                    if (*(uint*)node == StShaderModuleCreateInfo)
                        StripCode(node);
                }
            }

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

        private static void StripCode(IntPtr shaderModuleCreateInfo)
        {
            ulong size = *(ulong*)(shaderModuleCreateInfo + VkOffsets.ShaderModuleCodeSize);
            IntPtr code = *(IntPtr*)(shaderModuleCreateInfo + VkOffsets.ShaderModuleCode);
            if (code == IntPtr.Zero || size < 20 || (size & 3) != 0 || size > int.MaxValue)
                return;

            int words = Spirv.StripViewportIndex((uint*)code, (int)(size / 4));
            if (words < 0)
            {
                if (!ReportedShader)
                {
                    ReportedShader = true;
                    Utils.LogError("[VulkanImpls] multiViewport: a shader reads the viewport index, it is left as it is.");
                }
                return;
            }

            *(ulong*)(shaderModuleCreateInfo + VkOffsets.ShaderModuleCodeSize) = (ulong)words * 4;
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
