using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// Stands in for fillModeNonSolid with a geometry shader that turns every triangle into its edges or
    /// corners. Face culling does not reach the edges, so both faces are drawn.
    /// </summary>
    internal static unsafe class FillModeNonSolid
    {
        internal sealed class PipelineRecord
        {
            public IntPtr Device;
            public IntPtr Wireframe;
            public bool Triangles;
            public bool DynamicTopology;
            public bool Tessellation;
            public bool VertexInputLibrary;
            public bool PreRasterizationLibrary;
        }

        internal sealed class Plan
        {
            public int Index;
            public IntPtr Info;
            public IntPtr LibraryNode;
            public IntPtr Libraries;
            public IntPtr OriginalLibraries;
            public PipelineRecord Record = new PipelineRecord();
        }

        private const uint PolygonModeFill = 0;
        private const uint PolygonModePoint = 2;

        private const uint StShaderModuleCreateInfo = 16;
        private const uint StPipelineShaderStageCreateInfo = 18;
        private const uint StPipelineLibraryCreateInfoKhr = 1000290000;
        private const uint StGraphicsPipelineLibraryCreateInfoExt = 1000320002;

        private const uint LibraryVertexInputInterface = 1;
        private const uint LibraryPreRasterizationShaders = 2;

        private const uint PipelineCreateDerivative = 4;
        private const int DynamicStatePrimitiveTopology = 1000267002;

        private const uint StageVertex = 1;
        private const uint StageTessellationEvaluation = 4;
        private const uint StageGeometry = 8;
        private const uint StageTask = 0x40;
        private const uint StageMesh = 0x80;

        private const int TopologyTriangleList = 3;
        private const int TopologyTriangleFan = 5;
        private const int TopologyPatchList = 10;
        private const int BindPointGraphics = 0;

        private static readonly HashSet<string> Reported = new HashSet<string>();

        private static void Complain(string reason)
        {
            if (Reported.Add(reason))
                Utils.LogError("[VulkanImpls] fillModeNonSolid: " + reason + ", drawn solid.");
        }

        internal static void PreparePipeline(VulkanStandInState state, GenState st, IntPtr device, int bits, IntPtr info, int index)
        {
            IntPtr raster = *(IntPtr*)(info + VkOffsets.PipelineRasterization);
            uint polygonMode = raster != IntPtr.Zero ? *(uint*)(raster + VkOffsets.RasterizationPolygonMode) : PolygonModeFill;
            bool discard = raster != IntPtr.Zero && *(uint*)(raster + VkOffsets.RasterizationDiscard) != 0;
            if (raster != IntPtr.Zero)
                *(uint*)(raster + VkOffsets.RasterizationPolygonMode) = PolygonModeFill;

            uint libraryFlags = 0;
            IntPtr libraryNode = IntPtr.Zero;
            for (IntPtr node = *(IntPtr*)(info + VkOffsets.PipelinePNext); node != IntPtr.Zero; node = *(IntPtr*)(node + VkOffsets.NodePNext))
            {
                uint sType = *(uint*)node;
                if (sType == StGraphicsPipelineLibraryCreateInfoExt)
                    libraryFlags = *(uint*)(node + VkOffsets.LibraryFlags);
                else if (sType == StPipelineLibraryCreateInfoKhr)
                    libraryNode = node;
            }

            bool monolithic = libraryFlags == 0 && libraryNode == IntPtr.Zero;
            bool vertexInputHere = monolithic || (libraryFlags & LibraryVertexInputInterface) != 0;
            bool preRasterHere = monolithic || (libraryFlags & LibraryPreRasterizationShaders) != 0;

            Plan plan = new Plan { Index = index };
            PipelineRecord record = plan.Record;
            record.Device = device;
            record.VertexInputLibrary = vertexInputHere && !preRasterHere;
            record.PreRasterizationLibrary = preRasterHere && !vertexInputHere;
            record.Tessellation = HasStage(info, StageTessellationEvaluation);
            if (vertexInputHere)
            {
                IntPtr assembly = *(IntPtr*)(info + VkOffsets.PipelineInputAssembly);
                record.DynamicTopology = HasDynamicState(info, DynamicStatePrimitiveTopology);
                record.Triangles = assembly != IntPtr.Zero && IsTriangles(*(int*)(assembly + VkOffsets.InputAssemblyTopology), record.Tessellation);
            }

            if (libraryNode != IntPtr.Zero)
            {
                uint count = *(uint*)(libraryNode + VkOffsets.LibraryCount);
                IntPtr handles = *(IntPtr*)(libraryNode + VkOffsets.LibraryHandles);
                IntPtr variants = count != 0 ? st.Alloc(BrovVulkGenStruct.CheckedBytes(count, 8)) : IntPtr.Zero;
                bool any = false;
                for (uint k = 0; k < count; k++)
                {
                    IntPtr library = Marshal.ReadIntPtr(handles, (int)k * 8);
                    IntPtr use = library;
                    if (state.Pipelines.TryGetValue(library, out PipelineRecord? linked))
                    {
                        if (linked.Wireframe != IntPtr.Zero)
                        {
                            use = linked.Wireframe;
                            any = true;
                        }

                        if (linked.VertexInputLibrary && !vertexInputHere)
                        {
                            record.Triangles = linked.Triangles;
                            record.DynamicTopology = linked.DynamicTopology;
                        }

                        if (linked.PreRasterizationLibrary)
                            record.Tessellation = linked.Tessellation;
                    }

                    Marshal.WriteIntPtr(variants, (int)k * 8, use);
                }

                if (any)
                {
                    plan.Info = CopyInfo(st, info);
                    plan.LibraryNode = libraryNode;
                    plan.Libraries = variants;
                }
            }
            else if (polygonMode != PolygonModeFill && !discard && preRasterHere)
            {
                plan.Info = WireframeInfo(state, st, device, bits, info, polygonMode == PolygonModePoint);
            }

            if (plan.Info != IntPtr.Zero || record.VertexInputLibrary)
                state.Plans.Add(plan);
        }

        private static IntPtr WireframeInfo(VulkanStandInState state, GenState st, IntPtr device, int bits, IntPtr info, bool points)
        {
            if ((bits & VulkanStandIns.HostGeometryShaderBit) == 0)
            {
                Complain("the host has no geometry shader");
                return IntPtr.Zero;
            }

            IntPtr stages = *(IntPtr*)(info + VkOffsets.PipelineStages);
            uint stageCount = *(uint*)(info + VkOffsets.PipelineStageCount);
            IntPtr chosen = IntPtr.Zero;
            uint chosenModel = Spirv.ModelVertex;
            for (uint i = 0; i < stageCount; i++)
            {
                IntPtr stage = stages + (int)(i * (uint)VkOffsets.StageSize);
                uint kind = *(uint*)(stage + VkOffsets.StageStage);
                if ((kind & (StageGeometry | StageMesh | StageTask)) != 0)
                {
                    Complain("the pipeline already has a geometry or mesh stage");
                    return IntPtr.Zero;
                }

                if (kind == StageTessellationEvaluation)
                {
                    chosen = stage;
                    chosenModel = Spirv.ModelTessellationEvaluation;
                }
                else if (kind == StageVertex && chosen == IntPtr.Zero)
                {
                    chosen = stage;
                }
            }

            if (chosen == IntPtr.Zero)
                return IntPtr.Zero;

            SpirvInterface? last = StageInterface(state, chosen, chosenModel);
            if (last == null)
            {
                Complain("the shader code is not available");
                return IntPtr.Zero;
            }

            uint[]? words = SpirvPassThrough.Build(last, points,
                (bits & VulkanStandIns.HostGeometryPointSizeBit) != 0,
                (bits & VulkanStandIns.HostClipDistanceBit) != 0,
                (bits & VulkanStandIns.HostCullDistanceBit) != 0);
            if (words == null)
            {
                Complain("the shader outputs cannot pass through a geometry shader");
                return IntPtr.Zero;
            }

            IntPtr code = st.Alloc(words.Length * 4);
            fixed (uint* source = words)
                Buffer.MemoryCopy(source, (void*)code, words.Length * 4, words.Length * 4);
            IntPtr moduleInfo = st.Alloc(VkOffsets.ShaderModuleSize);
            *(uint*)moduleInfo = StShaderModuleCreateInfo;
            *(ulong*)(moduleInfo + VkOffsets.ShaderModuleCodeSize) = (ulong)words.Length * 4;
            *(IntPtr*)(moduleInfo + VkOffsets.ShaderModuleCode) = code;

            IntPtr module = IntPtr.Zero;
            if (BrovVulkApi.vkCreateShaderModule(device, moduleInfo, IntPtr.Zero, (IntPtr)(&module)) < 0 || module == IntPtr.Zero)
            {
                Complain("the geometry shader module could not be created");
                return IntPtr.Zero;
            }

            state.TemporaryModules.Add(module);

            IntPtr newStages = st.Alloc(BrovVulkGenStruct.CheckedBytes(stageCount + 1, VkOffsets.StageSize));
            Buffer.MemoryCopy((void*)stages, (void*)newStages, stageCount * (ulong)VkOffsets.StageSize, stageCount * (ulong)VkOffsets.StageSize);
            IntPtr added = newStages + (int)(stageCount * (uint)VkOffsets.StageSize);
            IntPtr name = st.Alloc(8);
            *(uint*)name = 0x6E69616Du;
            *(uint*)added = StPipelineShaderStageCreateInfo;
            *(uint*)(added + VkOffsets.StageStage) = StageGeometry;
            *(IntPtr*)(added + VkOffsets.StageModule) = module;
            *(IntPtr*)(added + VkOffsets.StageName) = name;

            IntPtr copy = CopyInfo(st, info);
            *(uint*)(copy + VkOffsets.PipelineStageCount) = stageCount + 1;
            *(IntPtr*)(copy + VkOffsets.PipelineStages) = newStages;
            return copy;
        }

        private static SpirvInterface? StageInterface(VulkanStandInState state, IntPtr stage, uint model)
        {
            IntPtr module = *(IntPtr*)(stage + VkOffsets.StageModule);
            if (module != IntPtr.Zero)
                return state.Modules.TryGetValue(module, out ShaderModuleRecord? record) && record.InterfaceModel == model ? record.Interface : null;

            for (IntPtr node = *(IntPtr*)(stage + VkOffsets.StagePNext); node != IntPtr.Zero; node = *(IntPtr*)(node + VkOffsets.NodePNext))
            {
                if (*(uint*)node != StShaderModuleCreateInfo)
                    continue;

                ulong size = *(ulong*)(node + VkOffsets.ShaderModuleCodeSize);
                IntPtr code = *(IntPtr*)(node + VkOffsets.ShaderModuleCode);
                if (code == IntPtr.Zero || size < 20 || (size & 3) != 0 || size > int.MaxValue)
                    return null;

                IntPtr namePointer = *(IntPtr*)(stage + VkOffsets.StageName);
                string? name = namePointer != IntPtr.Zero ? Marshal.PtrToStringAnsi(namePointer) : null;
                return Spirv.ParseInterface((uint*)code, (int)(size / 4), model, name);
            }

            return null;
        }

        private static IntPtr CopyInfo(GenState st, IntPtr info)
        {
            IntPtr copy = st.Alloc(VkOffsets.PipelineSize);
            Buffer.MemoryCopy((void*)info, (void*)copy, VkOffsets.PipelineSize, VkOffsets.PipelineSize);
            *(uint*)(copy + VkOffsets.PipelineFlags) &= ~PipelineCreateDerivative;
            *(IntPtr*)(copy + VkOffsets.PipelineBaseHandle) = IntPtr.Zero;
            *(int*)(copy + VkOffsets.PipelineBaseIndex) = -1;
            return copy;
        }

        private static bool HasStage(IntPtr info, uint kind)
        {
            IntPtr stages = *(IntPtr*)(info + VkOffsets.PipelineStages);
            uint count = *(uint*)(info + VkOffsets.PipelineStageCount);
            for (uint i = 0; i < count; i++)
            {
                if ((*(uint*)(stages + (int)(i * (uint)VkOffsets.StageSize) + VkOffsets.StageStage) & kind) != 0)
                    return true;
            }

            return false;
        }

        private static bool HasDynamicState(IntPtr info, int wanted)
        {
            IntPtr dynamic = *(IntPtr*)(info + VkOffsets.PipelineDynamicState);
            if (dynamic == IntPtr.Zero)
                return false;

            uint count = *(uint*)(dynamic + VkOffsets.DynamicStateCount);
            IntPtr states = *(IntPtr*)(dynamic + VkOffsets.DynamicStates);
            for (uint i = 0; i < count && states != IntPtr.Zero; i++)
            {
                if (*(int*)(states + (int)(i * 4)) == wanted)
                    return true;
            }

            return false;
        }

        private static bool IsTriangles(int topology, bool tessellation)
        {
            return (topology >= TopologyTriangleList && topology <= TopologyTriangleFan) || (topology == TopologyPatchList && tessellation);
        }

        internal static void FinishPipelines(VulkanStandInState state, GenState st, IntPtr device, IntPtr cache, IntPtr pipelines, int result)
        {
            try
            {
                if (result < 0 || pipelines == IntPtr.Zero)
                    return;

                List<Plan> pending = new List<Plan>();
                foreach (Plan plan in state.Plans)
                {
                    IntPtr canonical = Marshal.ReadIntPtr(pipelines, plan.Index * 8);
                    if (canonical == IntPtr.Zero)
                        continue;

                    if (plan.Info == IntPtr.Zero)
                        state.Pipelines[canonical] = plan.Record;
                    else
                        pending.Add(plan);
                }

                if (pending.Count == 0)
                    return;

                IntPtr infos = st.Alloc(BrovVulkGenStruct.CheckedBytes((uint)pending.Count, VkOffsets.PipelineSize));
                IntPtr created = st.Alloc(BrovVulkGenStruct.CheckedBytes((uint)pending.Count, 8));
                for (int k = 0; k < pending.Count; k++)
                {
                    Plan plan = pending[k];
                    Buffer.MemoryCopy((void*)plan.Info, (void*)(infos + k * VkOffsets.PipelineSize), VkOffsets.PipelineSize, VkOffsets.PipelineSize);
                    if (plan.LibraryNode != IntPtr.Zero)
                    {
                        plan.OriginalLibraries = *(IntPtr*)(plan.LibraryNode + VkOffsets.LibraryHandles);
                        *(IntPtr*)(plan.LibraryNode + VkOffsets.LibraryHandles) = plan.Libraries;
                    }
                }

                try
                {
                    BrovVulkApi.vkCreateGraphicsPipelines(device, cache, (uint)pending.Count, infos, IntPtr.Zero, created);
                }
                finally
                {
                    foreach (Plan plan in pending)
                    {
                        if (plan.LibraryNode != IntPtr.Zero)
                            *(IntPtr*)(plan.LibraryNode + VkOffsets.LibraryHandles) = plan.OriginalLibraries;
                    }
                }

                for (int k = 0; k < pending.Count; k++)
                {
                    Plan plan = pending[k];
                    IntPtr canonical = Marshal.ReadIntPtr(pipelines, plan.Index * 8);
                    IntPtr wireframe = Marshal.ReadIntPtr(created, k * 8);
                    if (wireframe == IntPtr.Zero)
                    {
                        Complain("the wireframe pipeline could not be created");
                        if (plan.Record.VertexInputLibrary)
                            state.Pipelines[canonical] = plan.Record;
                        continue;
                    }

                    plan.Record.Wireframe = wireframe;
                    state.Pipelines[canonical] = plan.Record;
                }
            }
            finally
            {
                foreach (IntPtr module in state.TemporaryModules)
                    BrovVulkApi.vkDestroyShaderModule(device, module, IntPtr.Zero);
                state.TemporaryModules.Clear();
                state.Plans.Clear();
            }
        }

        internal static void DestroyPipeline(VulkanStandInState state, IntPtr device, IntPtr pipeline)
        {
            if (state.Pipelines.Remove(pipeline, out PipelineRecord? record) && record.Wireframe != IntPtr.Zero)
                BrovVulkApi.vkDestroyPipeline(device, record.Wireframe, IntPtr.Zero);
        }

        internal static void ReleaseDevice(VulkanStandInState state, IntPtr device)
        {
            List<IntPtr> gone = new List<IntPtr>();
            foreach (KeyValuePair<IntPtr, PipelineRecord> entry in state.Pipelines)
            {
                if (device != IntPtr.Zero && entry.Value.Device != device)
                    continue;

                if (entry.Value.Wireframe != IntPtr.Zero)
                    BrovVulkApi.vkDestroyPipeline(entry.Value.Device, entry.Value.Wireframe, IntPtr.Zero);
                gone.Add(entry.Key);
            }

            foreach (IntPtr key in gone)
                state.Pipelines.Remove(key);

            gone.Clear();
            foreach (KeyValuePair<IntPtr, ShaderModuleRecord> entry in state.Modules)
            {
                if (device == IntPtr.Zero || entry.Value.Device == device)
                    gone.Add(entry.Key);
            }

            foreach (IntPtr key in gone)
                state.Modules.Remove(key);
        }

        private static CommandBufferRecord Record(VulkanStandInState state, IntPtr commandBuffer)
        {
            if (!state.CommandBuffers.TryGetValue(commandBuffer, out CommandBufferRecord? record))
                state.CommandBuffers[commandBuffer] = record = new CommandBufferRecord();
            return record;
        }

        internal static IntPtr Bind(VulkanStandInState state, IntPtr commandBuffer, int bindPoint, IntPtr pipeline)
        {
            if (bindPoint != BindPointGraphics || !state.WireframeActive)
                return pipeline;

            CommandBufferRecord record = Record(state, commandBuffer);
            record.Bound = pipeline;
            record.BoundWireframe = false;
            if (!state.Pipelines.TryGetValue(pipeline, out PipelineRecord? info) || info.Wireframe == IntPtr.Zero)
                return pipeline;

            bool wireframe = info.DynamicTopology ? IsTriangles(record.Topology, info.Tessellation) : info.Triangles;
            record.BoundWireframe = wireframe;
            return wireframe ? info.Wireframe : pipeline;
        }

        internal static void SetTopology(VulkanStandInState state, IntPtr commandBuffer, int topology)
        {
            if (!state.WireframeActive)
                return;

            CommandBufferRecord record = Record(state, commandBuffer);
            record.Topology = topology;
            if (record.Bound == IntPtr.Zero || !state.Pipelines.TryGetValue(record.Bound, out PipelineRecord? info)
                || info.Wireframe == IntPtr.Zero || !info.DynamicTopology)
                return;

            bool wireframe = IsTriangles(topology, info.Tessellation);
            if (wireframe == record.BoundWireframe)
                return;

            record.BoundWireframe = wireframe;
            BrovVulkApi.vkCmdBindPipeline(commandBuffer, BindPointGraphics, wireframe ? info.Wireframe : record.Bound);
        }
    }
}
