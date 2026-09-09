using System;
using System.Collections.Generic;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// Stands in for VK_KHR_maintenance6. The *2 descriptor commands become one Vulkan 1.0 command per bind
    /// point their stages name, a null index buffer becomes a zero filled buffer, and the properties struct
    /// answers with the minimum the extension guarantees.
    /// </summary>
    internal static unsafe class Maintenance6
    {
        // A null index buffer reads zero at any index, which no real buffer can do, so the substitute caps
        // how many indices a draw may take.
        private const int NullIndexBytes = 1 << 22;
        private const uint StBufferCreateInfo = 12;
        private const uint StMemoryAllocateInfo = 5;
        private const uint BufferUsageIndexBuffer = 0x40;
        private const uint MemoryHostVisibleCoherent = 0x6;
        private const ulong WholeSize = ulong.MaxValue;

        private const int BindPointGraphics = 0;
        private const int BindPointCompute = 1;
        private const int BindPointRayTracing = 1000165000;
        private const uint StagesGraphics = 0x1F | 0x40 | 0x80;
        private const uint StageCompute = 0x20;
        private const uint StagesRayTracing = 0x3F00;
        private const uint StagesAll = 0x7FFFFFFF;

        private static readonly HashSet<string> Reported = new HashSet<string>(StringComparer.Ordinal);

        private static class L
        {
            internal static readonly int BindStages = BrovVulkLayout.MemberOffset["VkBindDescriptorSetsInfo.stageFlags"];
            internal static readonly int BindLayout = BrovVulkLayout.MemberOffset["VkBindDescriptorSetsInfo.layout"];
            internal static readonly int BindFirstSet = BrovVulkLayout.MemberOffset["VkBindDescriptorSetsInfo.firstSet"];
            internal static readonly int BindSetCount = BrovVulkLayout.MemberOffset["VkBindDescriptorSetsInfo.descriptorSetCount"];
            internal static readonly int BindSets = BrovVulkLayout.MemberOffset["VkBindDescriptorSetsInfo.pDescriptorSets"];
            internal static readonly int BindOffsetCount = BrovVulkLayout.MemberOffset["VkBindDescriptorSetsInfo.dynamicOffsetCount"];
            internal static readonly int BindOffsets = BrovVulkLayout.MemberOffset["VkBindDescriptorSetsInfo.pDynamicOffsets"];

            internal static readonly int PushSetStages = BrovVulkLayout.MemberOffset["VkPushDescriptorSetInfo.stageFlags"];
            internal static readonly int PushSetLayout = BrovVulkLayout.MemberOffset["VkPushDescriptorSetInfo.layout"];
            internal static readonly int PushSetSet = BrovVulkLayout.MemberOffset["VkPushDescriptorSetInfo.set"];
            internal static readonly int PushSetWriteCount = BrovVulkLayout.MemberOffset["VkPushDescriptorSetInfo.descriptorWriteCount"];
            internal static readonly int PushSetWrites = BrovVulkLayout.MemberOffset["VkPushDescriptorSetInfo.pDescriptorWrites"];

            internal static readonly int PushStages = BrovVulkLayout.MemberOffset["VkPushConstantsInfo.stageFlags"];
            internal static readonly int PushLayout = BrovVulkLayout.MemberOffset["VkPushConstantsInfo.layout"];
            internal static readonly int PushOffset = BrovVulkLayout.MemberOffset["VkPushConstantsInfo.offset"];
            internal static readonly int PushSize = BrovVulkLayout.MemberOffset["VkPushConstantsInfo.size"];
            internal static readonly int PushValues = BrovVulkLayout.MemberOffset["VkPushConstantsInfo.pValues"];

            internal static readonly int PropertiesMultipleLayers = BrovVulkLayout.MemberOffset["VkPhysicalDeviceMaintenance6Properties.blockTexelViewCompatibleMultipleLayers"];
            internal static readonly int PropertiesCombinedCount = BrovVulkLayout.MemberOffset["VkPhysicalDeviceMaintenance6Properties.maxCombinedImageSamplerDescriptorCount"];
            internal static readonly int PropertiesClampInputs = BrovVulkLayout.MemberOffset["VkPhysicalDeviceMaintenance6Properties.fragmentShadingRateClampCombinerInputs"];

            internal static readonly int BufferCreateSize = BrovVulkLayout.StructSize["VkBufferCreateInfo"];
            internal static readonly int BufferSize = BrovVulkLayout.MemberOffset["VkBufferCreateInfo.size"];
            internal static readonly int BufferUsage = BrovVulkLayout.MemberOffset["VkBufferCreateInfo.usage"];
            internal static readonly int RequirementsSize = BrovVulkLayout.StructSize["VkMemoryRequirements"];
            internal static readonly int RequirementsBytes = BrovVulkLayout.MemberOffset["VkMemoryRequirements.size"];
            internal static readonly int RequirementsTypes = BrovVulkLayout.MemberOffset["VkMemoryRequirements.memoryTypeBits"];
            internal static readonly int AllocateSize = BrovVulkLayout.StructSize["VkMemoryAllocateInfo"];
            internal static readonly int AllocateBytes = BrovVulkLayout.MemberOffset["VkMemoryAllocateInfo.allocationSize"];
            internal static readonly int AllocateType = BrovVulkLayout.MemberOffset["VkMemoryAllocateInfo.memoryTypeIndex"];
            internal static readonly int MemoryPropertiesSize = BrovVulkLayout.StructSize["VkPhysicalDeviceMemoryProperties"];
            internal static readonly int MemoryTypeCount = BrovVulkLayout.MemberOffset["VkPhysicalDeviceMemoryProperties.memoryTypeCount"];
            internal static readonly int MemoryTypes = BrovVulkLayout.MemberOffset["VkPhysicalDeviceMemoryProperties.memoryTypes"];
            internal static readonly int MemoryTypeSize = BrovVulkLayout.StructSize["VkMemoryType"];
            internal static readonly int MemoryTypeFlags = BrovVulkLayout.MemberOffset["VkMemoryType.propertyFlags"];
        }

        internal sealed class NullIndexRecord
        {
            public IntPtr Buffer;
            public IntPtr Memory;
        }

        private static void Complain(string reason)
        {
            if (Reported.Add(reason))
                Utils.LogError("[VulkanImpls] VK_KHR_maintenance6: " + reason + ".");
        }

        internal static void Properties(IntPtr node)
        {
            *(uint*)(node + L.PropertiesMultipleLayers) = 0;
            *(uint*)(node + L.PropertiesCombinedCount) = 1;
            *(uint*)(node + L.PropertiesClampInputs) = 0;
        }

        internal static bool BindDescriptorSets(IntPtr commandBuffer, IntPtr info)
        {
            IntPtr layout = *(IntPtr*)(info + L.BindLayout);
            if (layout == IntPtr.Zero)
            {
                Complain("descriptor sets bound without a pipeline layout are dropped");
                return true;
            }

            uint stages = *(uint*)(info + L.BindStages);
            uint firstSet = *(uint*)(info + L.BindFirstSet);
            uint setCount = *(uint*)(info + L.BindSetCount);
            IntPtr sets = *(IntPtr*)(info + L.BindSets);
            uint offsetCount = *(uint*)(info + L.BindOffsetCount);
            IntPtr offsets = *(IntPtr*)(info + L.BindOffsets);

            if ((stages & (StagesGraphics | StageCompute | StagesRayTracing)) == 0)
            {
                Complain("descriptor sets bound for no pipeline bind point are dropped");
                return true;
            }

            if ((stages & StagesGraphics) != 0)
                BindRuns(commandBuffer, BindPointGraphics, layout, firstSet, setCount, sets, offsetCount, offsets);
            if ((stages & StageCompute) != 0)
                BindRuns(commandBuffer, BindPointCompute, layout, firstSet, setCount, sets, offsetCount, offsets);
            if ((stages & StagesRayTracing) != 0 && stages != StagesAll)
                BindRuns(commandBuffer, BindPointRayTracing, layout, firstSet, setCount, sets, offsetCount, offsets);
            return true;
        }

        internal static bool HasNullSet(uint setCount, IntPtr sets)
        {
            if (sets == IntPtr.Zero)
                return false;

            for (uint i = 0; i < setCount; i++)
                if (*(IntPtr*)(sets + (int)(i * 8)) == IntPtr.Zero)
                    return true;

            return false;
        }

        // A null element leaves that set undisturbed, so only the runs around it are bound.
        internal static bool BindRuns(IntPtr commandBuffer, int bindPoint, IntPtr layout, uint firstSet, uint setCount, IntPtr sets, uint offsetCount, IntPtr offsets)
        {
            if (!HasNullSet(setCount, sets))
            {
                BrovVulkApi.vkCmdBindDescriptorSets(commandBuffer, bindPoint, layout, firstSet, setCount, sets, offsetCount, offsets);
                return true;
            }

            if (offsetCount != 0)
            {
                Complain("descriptor sets with a null element and dynamic offsets are dropped");
                return true;
            }

            for (uint i = 0; i < setCount; )
            {
                if (*(IntPtr*)(sets + (int)(i * 8)) == IntPtr.Zero)
                {
                    i++;
                    continue;
                }

                uint start = i;
                while (i < setCount && *(IntPtr*)(sets + (int)(i * 8)) != IntPtr.Zero)
                    i++;

                BrovVulkApi.vkCmdBindDescriptorSets(commandBuffer, bindPoint, layout, firstSet + start, i - start, sets + (int)(start * 8), 0, IntPtr.Zero);
            }

            return true;
        }

        internal static bool PushDescriptorSet(IntPtr commandBuffer, IntPtr info)
        {
            IntPtr layout = *(IntPtr*)(info + L.PushSetLayout);
            if (layout == IntPtr.Zero)
            {
                Complain("push descriptors without a pipeline layout are dropped");
                return true;
            }

            uint stages = *(uint*)(info + L.PushSetStages);
            uint set = *(uint*)(info + L.PushSetSet);
            uint writeCount = *(uint*)(info + L.PushSetWriteCount);
            IntPtr writes = *(IntPtr*)(info + L.PushSetWrites);

            if ((stages & StagesGraphics) != 0)
                BrovVulkApi.vkCmdPushDescriptorSet(commandBuffer, BindPointGraphics, layout, set, writeCount, writes);
            if ((stages & StageCompute) != 0)
                BrovVulkApi.vkCmdPushDescriptorSet(commandBuffer, BindPointCompute, layout, set, writeCount, writes);
            if ((stages & StagesRayTracing) != 0 && stages != StagesAll)
                BrovVulkApi.vkCmdPushDescriptorSet(commandBuffer, BindPointRayTracing, layout, set, writeCount, writes);
            if ((stages & (StagesGraphics | StageCompute | StagesRayTracing)) == 0)
                Complain("push descriptors for no pipeline bind point are dropped");
            return true;
        }

        internal static bool PushConstants(IntPtr commandBuffer, IntPtr info)
        {
            IntPtr layout = *(IntPtr*)(info + L.PushLayout);
            if (layout == IntPtr.Zero)
            {
                Complain("push constants without a pipeline layout are dropped");
                return true;
            }

            BrovVulkApi.vkCmdPushConstants(commandBuffer, layout, *(uint*)(info + L.PushStages), *(uint*)(info + L.PushOffset), *(uint*)(info + L.PushSize), *(IntPtr*)(info + L.PushValues));
            return true;
        }

        internal static IntPtr NullIndexBuffer(VulkanStandInState state, GenState st, IntPtr device)
        {
            if (!state.NullIndexBuffers.TryGetValue(device, out NullIndexRecord? record))
            {
                record = Create(st, device);
                state.NullIndexBuffers[device] = record;
            }

            return record.Buffer;
        }

        private static NullIndexRecord Create(GenState st, IntPtr device)
        {
            NullIndexRecord record = new NullIndexRecord();

            byte* createInfo = stackalloc byte[L.BufferCreateSize];
            new Span<byte>(createInfo, L.BufferCreateSize).Clear();
            *(uint*)createInfo = StBufferCreateInfo;
            *(ulong*)(createInfo + L.BufferSize) = NullIndexBytes;
            *(uint*)(createInfo + L.BufferUsage) = BufferUsageIndexBuffer;

            IntPtr buffer = IntPtr.Zero;
            if (BrovVulkApi.vkCreateBuffer(device, (IntPtr)createInfo, IntPtr.Zero, (IntPtr)(&buffer)) < 0 || buffer == IntPtr.Zero)
            {
                Complain("the zero index buffer could not be created, null index binds stay null");
                return record;
            }

            byte* requirements = stackalloc byte[L.RequirementsSize];
            new Span<byte>(requirements, L.RequirementsSize).Clear();
            BrovVulkApi.vkGetBufferMemoryRequirements(device, buffer, (IntPtr)requirements);
            ulong bytes = *(ulong*)(requirements + L.RequirementsBytes);

            st.TryGetDevicePhysical(device, out IntPtr physicalDevice);
            int type = HostVisibleType(physicalDevice, *(uint*)(requirements + L.RequirementsTypes));

            byte* allocate = stackalloc byte[L.AllocateSize];
            new Span<byte>(allocate, L.AllocateSize).Clear();
            *(uint*)allocate = StMemoryAllocateInfo;
            *(ulong*)(allocate + L.AllocateBytes) = bytes;
            *(uint*)(allocate + L.AllocateType) = (uint)Math.Max(type, 0);

            IntPtr memory = IntPtr.Zero;
            IntPtr mapped = IntPtr.Zero;
            if (type < 0
                || BrovVulkApi.vkAllocateMemory(device, (IntPtr)allocate, IntPtr.Zero, (IntPtr)(&memory)) < 0 || memory == IntPtr.Zero
                || BrovVulkApi.vkBindBufferMemory(device, buffer, memory, 0) < 0
                || BrovVulkApi.vkMapMemory(device, memory, 0, WholeSize, 0, (IntPtr)(&mapped)) < 0 || mapped == IntPtr.Zero)
            {
                Complain("the zero index buffer could not be backed, null index binds stay null");
                BrovVulkApi.vkDestroyBuffer(device, buffer, IntPtr.Zero);
                if (memory != IntPtr.Zero)
                    BrovVulkApi.vkFreeMemory(device, memory, IntPtr.Zero);
                return record;
            }

            new Span<byte>((void*)mapped, (int)Math.Min(bytes, int.MaxValue)).Clear();
            BrovVulkApi.vkUnmapMemory(device, memory);
            record.Buffer = buffer;
            record.Memory = memory;
            return record;
        }

        private static int HostVisibleType(IntPtr physicalDevice, uint allowed)
        {
            if (physicalDevice == IntPtr.Zero)
                return -1;

            byte* properties = stackalloc byte[L.MemoryPropertiesSize];
            new Span<byte>(properties, L.MemoryPropertiesSize).Clear();
            BrovVulkApi.vkGetPhysicalDeviceMemoryProperties(physicalDevice, (IntPtr)properties);
            uint count = *(uint*)(properties + L.MemoryTypeCount);
            for (uint i = 0; i < count && i < 32; i++)
            {
                uint flags = *(uint*)(properties + L.MemoryTypes + (int)(i * (uint)L.MemoryTypeSize) + L.MemoryTypeFlags);
                if ((allowed & (1u << (int)i)) != 0 && (flags & MemoryHostVisibleCoherent) == MemoryHostVisibleCoherent)
                    return (int)i;
            }

            return -1;
        }

        internal static void ReleaseDevice(VulkanStandInState state, IntPtr device)
        {
            List<IntPtr> gone = new List<IntPtr>();
            foreach (KeyValuePair<IntPtr, NullIndexRecord> entry in state.NullIndexBuffers)
            {
                if (device != IntPtr.Zero && entry.Key != device)
                    continue;

                if (entry.Value.Buffer != IntPtr.Zero)
                    BrovVulkApi.vkDestroyBuffer(entry.Key, entry.Value.Buffer, IntPtr.Zero);
                if (entry.Value.Memory != IntPtr.Zero)
                    BrovVulkApi.vkFreeMemory(entry.Key, entry.Value.Memory, IntPtr.Zero);
                gone.Add(entry.Key);
            }

            foreach (IntPtr key in gone)
                state.NullIndexBuffers.Remove(key);
        }
    }
}
