using System;
using System.Runtime.InteropServices;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// Stands in for shaderClipDistance, shaderCullDistance and the viewport index by moving those built-ins
    /// onto user locations and attaching the clip prologue to a monolithic pipeline's fragment shader. Cull
    /// distances only remove primitives, so ignoring them draws more and never less.
    /// </summary>
    internal static unsafe class ShaderPatches
    {
        private const uint StShaderModuleCreateInfo = 16;
        private const uint StPipelineLibraryCreateInfoKhr = 1000290000;
        private const uint StGraphicsPipelineLibraryCreateInfoExt = 1000320002;
        private const uint PipelineCreateLibrary = 0x800;

        private const uint StageVertex = 1;
        private const uint StageTessellationEvaluation = 4;
        private const uint StageGeometry = 8;
        private const uint StageFragment = 0x10;

        private static bool ReportedLeft;
        private static bool ReportedPrologue;
        private static bool ReportedAttached;

        internal static void Relocate(GenState st, IntPtr device, uint* words, int count, out SpirvModuleInfo info)
        {
            st.TryGetDevicePhysical(device, out IntPtr physicalDevice);
            Spirv.Relocate(words, count, VulkanStandIns.Gaps(physicalDevice).Relocation, out info);
            if (info.Left && !ReportedLeft)
            {
                ReportedLeft = true;
                Utils.LogError("[VulkanImpls] a shader uses a built-in the host lacks in a way that cannot move, it is left as it is.");
            }

            st.StandIns.PendingModule = info;
        }

        internal static void NoteModule(VulkanStandInState state, IntPtr device, int bits, uint* words, int count, IntPtr module)
        {
            SpirvModuleInfo info = state.PendingModule;
            state.PendingModule = default;

            ShaderModuleRecord record = new ShaderModuleRecord { Device = device, Models = info.Models, ClipOutputs = info.ClipOutputs };
            if ((bits & VulkanStandIns.FillModeNonSolidBit) != 0)
            {
                record.InterfaceModel = Spirv.ModelVertex;
                record.Interface = Spirv.ParseInterface(words, count, Spirv.ModelVertex, null);
                if (record.Interface == null)
                {
                    record.InterfaceModel = Spirv.ModelTessellationEvaluation;
                    record.Interface = Spirv.ParseInterface(words, count, Spirv.ModelTessellationEvaluation, null);
                }
            }

            if ((bits & VulkanStandIns.ClipDistanceBit) != 0 && info.Has(Spirv.ModelFragment))
                record.Code = new ReadOnlySpan<uint>(words, count).ToArray();

            if (record.Interface != null || record.Code != null || record.ClipOutputs != 0)
                state.Modules[module] = record;
        }

        internal static void PreparePipeline(GenState st, IntPtr device, int bits, IntPtr info)
        {
            VulkanStandInState state = st.StandIns;
            IntPtr stages = *(IntPtr*)(info + VkOffsets.PipelineStages);
            uint stageCount = *(uint*)(info + VkOffsets.PipelineStageCount);
            if (stages == IntPtr.Zero)
                return;

            int clipOutputs = 0;
            uint lastStage = 0;
            IntPtr fragment = IntPtr.Zero;
            uint* fragmentCode = null;
            int fragmentCount = 0;
            for (uint i = 0; i < stageCount; i++)
            {
                IntPtr stage = stages + (int)(i * (uint)VkOffsets.StageSize);
                uint kind = *(uint*)(stage + VkOffsets.StageStage);
                SpirvModuleInfo moduleInfo = default;
                IntPtr inline = InlineModule(stage);
                if (inline != IntPtr.Zero)
                {
                    ulong size = *(ulong*)(inline + VkOffsets.ShaderModuleCodeSize);
                    IntPtr code = *(IntPtr*)(inline + VkOffsets.ShaderModuleCode);
                    if (code != IntPtr.Zero && size >= 20 && (size & 3) == 0 && size <= int.MaxValue)
                    {
                        Relocate(st, device, (uint*)code, (int)(size / 4), out moduleInfo);
                        if (kind == StageFragment)
                        {
                            fragmentCode = (uint*)code;
                            fragmentCount = (int)(size / 4);
                        }
                    }
                }
                else if (state.Modules.TryGetValue(*(IntPtr*)(stage + VkOffsets.StageModule), out ShaderModuleRecord? record))
                {
                    moduleInfo.ClipOutputs = record.ClipOutputs;
                    moduleInfo.Models = record.Models;
                    if (kind == StageFragment && record.Code != null)
                    {
                        fragmentCount = record.Code.Length;
                        fragmentCode = (uint*)st.Alloc(fragmentCount * 4);
                        record.Code.AsSpan().CopyTo(new Span<uint>(fragmentCode, fragmentCount));
                    }
                }

                if (kind == StageFragment)
                    fragment = stage;
                else if (kind == StageGeometry || kind == StageTessellationEvaluation || kind == StageVertex)
                {
                    if (kind > lastStage)
                    {
                        lastStage = kind;
                        clipOutputs = moduleInfo.ClipOutputs;
                    }
                }
            }

            if ((bits & VulkanStandIns.ClipDistanceBit) == 0 || clipOutputs == 0 || fragment == IntPtr.Zero || fragmentCode == null || IsLibrary(info))
                return;

            st.TryGetDevicePhysical(device, out IntPtr physicalDevice);
            int location = VulkanStandIns.Gaps(physicalDevice).Relocation.Clip;
            uint[]? words = location >= 0 ? SpirvClipDiscard.Build(fragmentCode, fragmentCount, location, clipOutputs) : null;
            IntPtr module = words != null ? CreateModule(st, device, words) : IntPtr.Zero;
            if (module == IntPtr.Zero)
            {
                if (!ReportedPrologue)
                {
                    ReportedPrologue = true;
                    Utils.LogError("[VulkanImpls] shaderClipDistance: a fragment shader could not take the clip prologue, the pipeline draws unclipped.");
                }
                return;
            }

            if (!ReportedAttached)
            {
                ReportedAttached = true;
                Utils.LogError("[VulkanImpls] shaderClipDistance: fragment shaders discard against the relocated clip distances.");
            }

            state.TemporaryModules.Add(module);
            *(IntPtr*)(fragment + VkOffsets.StageModule) = module;
            IntPtr* link = (IntPtr*)(fragment + VkOffsets.StagePNext);
            while (*link != IntPtr.Zero)
            {
                if (*(uint*)*link == StShaderModuleCreateInfo)
                    *link = *(IntPtr*)(*link + VkOffsets.NodePNext);
                else
                    link = (IntPtr*)(*link + VkOffsets.NodePNext);
            }
        }

        internal static IntPtr CreateModule(GenState st, IntPtr device, uint[] words)
        {
            IntPtr code = st.Alloc(words.Length * 4);
            words.AsSpan().CopyTo(new Span<uint>((void*)code, words.Length));
            IntPtr moduleInfo = st.Alloc(VkOffsets.ShaderModuleSize);
            *(uint*)moduleInfo = StShaderModuleCreateInfo;
            *(ulong*)(moduleInfo + VkOffsets.ShaderModuleCodeSize) = (ulong)words.Length * 4;
            *(IntPtr*)(moduleInfo + VkOffsets.ShaderModuleCode) = code;

            IntPtr module = IntPtr.Zero;
            if (BrovVulkApi.vkCreateShaderModule(device, moduleInfo, IntPtr.Zero, (IntPtr)(&module)) < 0)
                return IntPtr.Zero;
            return module;
        }

        internal static IntPtr InlineModule(IntPtr stage)
        {
            for (IntPtr node = *(IntPtr*)(stage + VkOffsets.StagePNext); node != IntPtr.Zero; node = *(IntPtr*)(node + VkOffsets.NodePNext))
            {
                if (*(uint*)node == StShaderModuleCreateInfo)
                    return node;
            }

            return IntPtr.Zero;
        }

        private static bool IsLibrary(IntPtr info)
        {
            if ((*(uint*)(info + VkOffsets.PipelineFlags) & PipelineCreateLibrary) != 0)
                return true;

            for (IntPtr node = *(IntPtr*)(info + VkOffsets.PipelinePNext); node != IntPtr.Zero; node = *(IntPtr*)(node + VkOffsets.NodePNext))
            {
                uint sType = *(uint*)node;
                if (sType == StPipelineLibraryCreateInfoKhr || sType == StGraphicsPipelineLibraryCreateInfoExt)
                    return true;
            }

            return false;
        }
    }
}
