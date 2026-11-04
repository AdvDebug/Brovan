using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using Brovan.Core.Helpers;
using Brovan.Core.Settings;

namespace Brovan.Core.Emulation.OS.Windows
{
    // Queue timelines track CPU driver use. Hold BrovVulkDevice.Lock.
    internal sealed unsafe class BrovVulkRetire
    {
        internal sealed class Timeline
        {
            public IntPtr Semaphore;
            public ulong Submitted;
            public ulong Completed;
        }

        internal readonly struct Stamp
        {
            public readonly Timeline? Queue;
            public readonly ulong Value;
            private readonly (Timeline Queue, ulong Value)[]? _others;

            private Stamp(Timeline queue, ulong value, (Timeline, ulong)[]? others)
            {
                Queue = queue;
                Value = value;
                _others = others;
            }

            public bool Reached
            {
                get
                {
                    if (Queue != null && Queue.Completed < Value)
                        return false;
                    foreach ((Timeline queue, ulong value) in _others ?? Array.Empty<(Timeline, ulong)>())
                    {
                        if (queue.Completed < value)
                            return false;
                    }
                    return true;
                }
            }

            public Stamp Then(Timeline queue, ulong value)
            {
                List<(Timeline, ulong)>? others = null;
                if (Queue != null && Queue != queue && Queue.Completed < Value)
                    (others ??= new List<(Timeline, ulong)>()).Add((Queue, Value));
                foreach ((Timeline other, ulong otherValue) in _others ?? Array.Empty<(Timeline, ulong)>())
                {
                    if (other != queue && other.Completed < otherValue)
                        (others ??= new List<(Timeline, ulong)>()).Add((other, otherValue));
                }
                return new Stamp(queue, value, others?.ToArray());
            }
        }

        private sealed class DeviceRecord
        {
            public IntPtr Device;
            public readonly List<(IntPtr Queue, Timeline Timeline)> Queues = new List<(IntPtr, Timeline)>();
            public BrovVulkAddressSpace? Addresses;
            public int Queued;
        }

        private enum Kind : byte
        {
            Destroy,
            DestroyDevice,
            DestroyInstance,
            FreeMemory,
            FreeCommandBuffers,
            FreeDescriptorSets,
            Unpin,
            Retained,
            Unhold,
            FreeAddress,
        }

        private sealed class Entry
        {
            public DeviceRecord? Device;
            public ulong[] Targets = Array.Empty<ulong>();
            public Kind Kind;
            public uint Command;
            public string Type = string.Empty;
            public IntPtr Parent;
            public IntPtr Handle;
            public IntPtr[]? Handles;
            public IGuestMemory? Memory;
            public (IntPtr[] Blocks, long Bytes) Retained;
            public IntPtr Owner;
            public string? OwnerType;
            public (IntPtr Ptr, string Type)[]? Held;
            public ulong AddressBase;
            public ulong AddressSpan;
        }

        private static readonly int SubmitSize = BrovVulkLayout.StructSize["VkSubmitInfo"];
        private static readonly int SubmitPNext = BrovVulkLayout.MemberOffset["VkSubmitInfo.pNext"];
        private static readonly int SubmitWaitCount = BrovVulkLayout.MemberOffset["VkSubmitInfo.waitSemaphoreCount"];
        private static readonly int SubmitWaits = BrovVulkLayout.MemberOffset["VkSubmitInfo.pWaitSemaphores"];
        private static readonly int SubmitWaitStages = BrovVulkLayout.MemberOffset["VkSubmitInfo.pWaitDstStageMask"];
        private static readonly int SubmitBufferCount = BrovVulkLayout.MemberOffset["VkSubmitInfo.commandBufferCount"];
        private static readonly int SubmitBuffers = BrovVulkLayout.MemberOffset["VkSubmitInfo.pCommandBuffers"];
        private static readonly int SubmitSignalCount = BrovVulkLayout.MemberOffset["VkSubmitInfo.signalSemaphoreCount"];
        private static readonly int SubmitSignals = BrovVulkLayout.MemberOffset["VkSubmitInfo.pSignalSemaphores"];

        private static readonly int TimelineInfoSize = BrovVulkLayout.StructSize["VkTimelineSemaphoreSubmitInfo"];
        private static readonly int TimelineWaitCount = BrovVulkLayout.MemberOffset["VkTimelineSemaphoreSubmitInfo.waitSemaphoreValueCount"];
        private static readonly int TimelineWaits = BrovVulkLayout.MemberOffset["VkTimelineSemaphoreSubmitInfo.pWaitSemaphoreValues"];
        private static readonly int TimelineSignalCount = BrovVulkLayout.MemberOffset["VkTimelineSemaphoreSubmitInfo.signalSemaphoreValueCount"];
        private static readonly int TimelineSignals = BrovVulkLayout.MemberOffset["VkTimelineSemaphoreSubmitInfo.pSignalSemaphoreValues"];
        private static readonly int GroupSignalCount = BrovVulkLayout.MemberOffset["VkDeviceGroupSubmitInfo.signalSemaphoreCount"];
        private static readonly int GroupSignals = BrovVulkLayout.MemberOffset["VkDeviceGroupSubmitInfo.pSignalSemaphoreDeviceIndices"];

        private static readonly int Submit2Size = BrovVulkLayout.StructSize["VkSubmitInfo2"];
        private static readonly int Submit2WaitCount = BrovVulkLayout.MemberOffset["VkSubmitInfo2.waitSemaphoreInfoCount"];
        private static readonly int Submit2Waits = BrovVulkLayout.MemberOffset["VkSubmitInfo2.pWaitSemaphoreInfos"];
        private static readonly int Submit2BufferCount = BrovVulkLayout.MemberOffset["VkSubmitInfo2.commandBufferInfoCount"];
        private static readonly int Submit2Buffers = BrovVulkLayout.MemberOffset["VkSubmitInfo2.pCommandBufferInfos"];
        private static readonly int Submit2SignalCount = BrovVulkLayout.MemberOffset["VkSubmitInfo2.signalSemaphoreInfoCount"];
        private static readonly int Submit2Signals = BrovVulkLayout.MemberOffset["VkSubmitInfo2.pSignalSemaphoreInfos"];
        private static readonly int SemaphoreInfoSize = BrovVulkLayout.StructSize["VkSemaphoreSubmitInfo"];
        private static readonly int SemaphoreInfoSemaphore = BrovVulkLayout.MemberOffset["VkSemaphoreSubmitInfo.semaphore"];
        private static readonly int SemaphoreInfoValue = BrovVulkLayout.MemberOffset["VkSemaphoreSubmitInfo.value"];
        private static readonly int SemaphoreInfoStages = BrovVulkLayout.MemberOffset["VkSemaphoreSubmitInfo.stageMask"];
        private static readonly int BufferInfoSize = BrovVulkLayout.StructSize["VkCommandBufferSubmitInfo"];
        private static readonly int BufferInfoBuffer = BrovVulkLayout.MemberOffset["VkCommandBufferSubmitInfo.commandBuffer"];

        private static readonly int DeviceQueueInfoCount = BrovVulkLayout.MemberOffset["VkDeviceCreateInfo.queueCreateInfoCount"];
        private static readonly int DeviceQueueInfos = BrovVulkLayout.MemberOffset["VkDeviceCreateInfo.pQueueCreateInfos"];
        private static readonly int QueueInfoSize = BrovVulkLayout.StructSize["VkDeviceQueueCreateInfo"];
        private static readonly int QueueInfoFlags = BrovVulkLayout.MemberOffset["VkDeviceQueueCreateInfo.flags"];
        private static readonly int QueueInfoFamily = BrovVulkLayout.MemberOffset["VkDeviceQueueCreateInfo.queueFamilyIndex"];
        private static readonly int QueueInfoCount = BrovVulkLayout.MemberOffset["VkDeviceQueueCreateInfo.queueCount"];
        private static readonly int QueueInfo2Size = BrovVulkLayout.StructSize["VkDeviceQueueInfo2"];
        private static readonly int QueueInfo2Flags = BrovVulkLayout.MemberOffset["VkDeviceQueueInfo2.flags"];
        private static readonly int QueueInfo2Family = BrovVulkLayout.MemberOffset["VkDeviceQueueInfo2.queueFamilyIndex"];
        private static readonly int QueueInfo2Index = BrovVulkLayout.MemberOffset["VkDeviceQueueInfo2.queueIndex"];
        private static readonly int TypeInfoSize = BrovVulkLayout.StructSize["VkSemaphoreTypeCreateInfo"];
        private static readonly int TypeInfoType = BrovVulkLayout.MemberOffset["VkSemaphoreTypeCreateInfo.semaphoreType"];
        private static readonly int SemaphoreCreateSize = BrovVulkLayout.StructSize["VkSemaphoreCreateInfo"];
        private static readonly int SemaphoreCreateNext = BrovVulkLayout.MemberOffset["VkSemaphoreCreateInfo.pNext"];
        private static readonly int WaitInfoSize = BrovVulkLayout.StructSize["VkSemaphoreWaitInfo"];
        private static readonly int WaitInfoCount = BrovVulkLayout.MemberOffset["VkSemaphoreWaitInfo.semaphoreCount"];
        private static readonly int WaitInfoSemaphores = BrovVulkLayout.MemberOffset["VkSemaphoreWaitInfo.pSemaphores"];
        private static readonly int WaitInfoValues = BrovVulkLayout.MemberOffset["VkSemaphoreWaitInfo.pValues"];

        private readonly Dictionary<IntPtr, DeviceRecord> _devices = new Dictionary<IntPtr, DeviceRecord>();
        private readonly Dictionary<IntPtr, Timeline> _queues = new Dictionary<IntPtr, Timeline>();
        private readonly List<Entry> _entries = new List<Entry>();
        private readonly Dictionary<IntPtr, Stamp> _poolStamps = new Dictionary<IntPtr, Stamp>();
        private readonly Dictionary<uint, IntPtr> _importDevices = new Dictionary<uint, IntPtr>();
        private readonly List<IntPtr> _submitted = new List<IntPtr>();
        // A surface can be held by more than one device.
        private readonly Dictionary<(IntPtr Ptr, string Type), List<(IntPtr Device, int Count)>> _holds = new Dictionary<(IntPtr, string), List<(IntPtr, int)>>();
        private readonly Dictionary<(IntPtr Ptr, string Type), List<Entry>> _parked = new Dictionary<(IntPtr, string), List<Entry>>();
        private readonly List<int> _batchEnds = new List<int>();
        private readonly List<(int End, ulong Value)> _signals = new List<(int, ulong)>();
        private readonly List<IntPtr> _overflowed = new List<IntPtr>();
        private bool _overflowLogged;
        private int _stamped;
        private int _pending;

        public bool HasPending => _entries.Count != 0;

        public bool Active => _devices.Count != 0;

        public bool IsCpu(IntPtr device) => device != IntPtr.Zero && _devices.ContainsKey(device);

        public int AddDevice(IntPtr device, IntPtr createInfo)
        {
            DeviceRecord record = new DeviceRecord { Device = device };
            uint infoCount = *(uint*)(createInfo + DeviceQueueInfoCount);
            byte* infos = (byte*)*(IntPtr*)(createInfo + DeviceQueueInfos);
            byte* typeInfo = stackalloc byte[TypeInfoSize];
            byte* semaphoreInfo = stackalloc byte[SemaphoreCreateSize];
            byte* queueInfo = stackalloc byte[QueueInfo2Size];
            new Span<byte>(typeInfo, TypeInfoSize).Clear();
            new Span<byte>(semaphoreInfo, SemaphoreCreateSize).Clear();
            *(int*)typeInfo = BrovVulkConstants.VK_STRUCTURE_TYPE_SEMAPHORE_TYPE_CREATE_INFO;
            *(int*)(typeInfo + TypeInfoType) = BrovVulkConstants.VK_SEMAPHORE_TYPE_TIMELINE;
            *(int*)semaphoreInfo = BrovVulkConstants.VK_STRUCTURE_TYPE_SEMAPHORE_CREATE_INFO;
            *(IntPtr*)(semaphoreInfo + SemaphoreCreateNext) = (IntPtr)typeInfo;

            for (uint i = 0; infos != null && i < infoCount; i++)
            {
                byte* info = infos + (long)i * QueueInfoSize;
                uint flags = *(uint*)(info + QueueInfoFlags);
                uint family = *(uint*)(info + QueueInfoFamily);
                uint count = *(uint*)(info + QueueInfoCount);
                for (uint index = 0; index < count; index++)
                {
                    IntPtr queue = IntPtr.Zero;
                    if (flags == 0)
                    {
                        BrovVulkApi.vkGetDeviceQueue(device, family, index, (IntPtr)(&queue));
                    }
                    else
                    {
                        new Span<byte>(queueInfo, QueueInfo2Size).Clear();
                        *(int*)queueInfo = BrovVulkConstants.VK_STRUCTURE_TYPE_DEVICE_QUEUE_INFO_2;
                        *(uint*)(queueInfo + QueueInfo2Flags) = flags;
                        *(uint*)(queueInfo + QueueInfo2Family) = family;
                        *(uint*)(queueInfo + QueueInfo2Index) = index;
                        BrovVulkApi.vkGetDeviceQueue2(device, (IntPtr)queueInfo, (IntPtr)(&queue));
                    }

                    IntPtr semaphore = IntPtr.Zero;
                    int rr = BrovVulkApi.vkCreateSemaphore(device, (IntPtr)semaphoreInfo, IntPtr.Zero, (IntPtr)(&semaphore));
                    if (rr < 0 || semaphore == IntPtr.Zero || queue == IntPtr.Zero)
                    {
                        if (semaphore != IntPtr.Zero)
                            BrovVulkApi.vkDestroySemaphore(device, semaphore, IntPtr.Zero);
                        DestroyTimelines(record);
                        return rr < 0 ? rr : BrovVulkConstants.VK_ERROR_INITIALIZATION_FAILED;
                    }

                    record.Queues.Add((queue, new Timeline { Semaphore = semaphore }));
                }
            }

            record.Addresses = BrovVulkAddressSpace.TryCreate();
            if (record.Addresses == null)
            {
                DestroyTimelines(record);
                return BrovVulkConstants.VK_ERROR_OUT_OF_HOST_MEMORY;
            }

            _devices[device] = record;
            foreach ((IntPtr queue, Timeline timeline) in record.Queues)
                _queues[queue] = timeline;
            return BrovVulkConstants.VK_SUCCESS;
        }

        public BrovVulkAddressSpace? AddressSpaceOf(IntPtr device) =>
            device != IntPtr.Zero && _devices.TryGetValue(device, out DeviceRecord? record) ? record.Addresses : null;

        public void FreeAddress(IntPtr device, ulong guest, ulong span, IntPtr record)
        {
            if (!TryAdd(device, new Entry { Kind = Kind.FreeAddress, Parent = device, Handle = record, AddressBase = guest, AddressSpan = span }))
                AddressSpaceOf(device)?.Free(guest, span, record);
        }

        private static void DestroyTimelines(DeviceRecord record)
        {
            foreach ((IntPtr _, Timeline timeline) in record.Queues)
                BrovVulkApi.vkDestroySemaphore(record.Device, timeline.Semaphore, IntPtr.Zero);
            record.Queues.Clear();
        }

        // Retirement waits for the relay too, since it still uses the guest semaphores.
        public static int QueueSubmit(GenState st, IGuestMemory inst, IntPtr queue, uint count, IntPtr submits, IntPtr fence)
        {
            BrovVulkRetire self = st.Retire;
            self.CollectBatches(st, count, submits, SubmitSize, SubmitBuffers, SubmitBufferCount, sizeof(IntPtr), 0);
            if (!self._queues.TryGetValue(queue, out Timeline? timeline) || count == 0)
                return BrovVulkApi.vkQueueSubmit(queue, count, submits, fence);
            if (!self.HasRoom(st))
                return BrovVulkConstants.VK_ERROR_OUT_OF_HOST_MEMORY;

            IntPtr split = st.Alloc(BrovVulkGenStruct.CheckedBytes(count * 4 + 1, SubmitSize));
            uint used = 0;
            ulong before = timeline.Submitted;
            bool open = false;
            for (uint i = 0; i < count; i++)
            {
                byte* guest = (byte*)submits + (long)i * SubmitSize;
                byte* work = (byte*)split + (long)used++ * SubmitSize;
                Buffer.MemoryCopy(guest, work, SubmitSize, SubmitSize);
                self._pending = self._batchEnds[(int)i];

                uint signals = *(uint*)(work + SubmitSignalCount);
                if (signals == 0)
                {
                    open = true;
                    continue;
                }

                IntPtr guestValues = IntPtr.Zero;
                uint guestValueCount = 0;
                for (byte* node = *(byte**)(work + SubmitPNext); node != null; node = *(byte**)(node + SubmitPNext))
                {
                    if (*(int*)node == BrovVulkConstants.VK_STRUCTURE_TYPE_TIMELINE_SEMAPHORE_SUBMIT_INFO)
                    {
                        guestValueCount = *(uint*)(node + TimelineSignalCount);
                        guestValues = *(IntPtr*)(node + TimelineSignals);
                        *(uint*)(node + TimelineSignalCount) = 0;
                        *(IntPtr*)(node + TimelineSignals) = IntPtr.Zero;
                    }
                    else if (*(int*)node == BrovVulkConstants.VK_STRUCTURE_TYPE_DEVICE_GROUP_SUBMIT_INFO)
                    {
                        *(uint*)(node + GroupSignalCount) = 0;
                        *(IntPtr*)(node + GroupSignals) = IntPtr.Zero;
                    }
                }

                IntPtr guestSignals = *(IntPtr*)(work + SubmitSignals);
                *(uint*)(work + SubmitSignalCount) = 0;
                *(IntPtr*)(work + SubmitSignals) = IntPtr.Zero;

                ulong value = Signal(st, timeline, (byte*)split + (long)used++ * SubmitSize);
                byte* relay = (byte*)split + (long)used++ * SubmitSize;
                BuildRelay(st, relay, timeline, value, signals, guestSignals, guestValueCount, guestValues);
                self.SignalBatch(st, timeline, (byte*)split + (long)used++ * SubmitSize);
                open = false;
            }

            if (open)
                self.SignalBatch(st, timeline, (byte*)split + (long)used++ * SubmitSize);

            int result = BrovVulkApi.vkQueueSubmit(queue, used, split, fence);
            self.Settle(st, timeline, result, before);
            return result;
        }

        public static int QueueSubmit2(GenState st, IGuestMemory inst, IntPtr queue, uint count, IntPtr submits, IntPtr fence)
        {
            BrovVulkRetire self = st.Retire;
            self.CollectBatches(st, count, submits, Submit2Size, Submit2Buffers, Submit2BufferCount, BufferInfoSize, BufferInfoBuffer);
            if (!self._queues.TryGetValue(queue, out Timeline? timeline) || count == 0)
                return BrovVulkApi.vkQueueSubmit2(queue, count, submits, fence);
            if (!self.HasRoom(st))
                return BrovVulkConstants.VK_ERROR_OUT_OF_HOST_MEMORY;

            IntPtr split = st.Alloc(BrovVulkGenStruct.CheckedBytes(count * 4 + 1, Submit2Size));
            uint used = 0;
            ulong before = timeline.Submitted;
            bool open = false;
            for (uint i = 0; i < count; i++)
            {
                byte* guest = (byte*)submits + (long)i * Submit2Size;
                byte* work = (byte*)split + (long)used++ * Submit2Size;
                Buffer.MemoryCopy(guest, work, Submit2Size, Submit2Size);
                self._pending = self._batchEnds[(int)i];

                uint signals = *(uint*)(work + Submit2SignalCount);
                if (signals == 0)
                {
                    open = true;
                    continue;
                }

                IntPtr guestSignals = *(IntPtr*)(work + Submit2Signals);
                *(uint*)(work + Submit2SignalCount) = 0;
                *(IntPtr*)(work + Submit2Signals) = IntPtr.Zero;

                ulong value = Signal2(st, timeline, (byte*)split + (long)used++ * Submit2Size);
                byte* relay = (byte*)split + (long)used++ * Submit2Size;
                new Span<byte>(relay, Submit2Size).Clear();
                *(int*)relay = BrovVulkConstants.VK_STRUCTURE_TYPE_SUBMIT_INFO_2;
                *(uint*)(relay + Submit2WaitCount) = 1;
                *(IntPtr*)(relay + Submit2Waits) = SemaphoreInfo(st, timeline, value);
                *(uint*)(relay + Submit2SignalCount) = signals;
                *(IntPtr*)(relay + Submit2Signals) = guestSignals;
                self.SignalBatch2(st, timeline, (byte*)split + (long)used++ * Submit2Size);
                open = false;
            }

            if (open)
                self.SignalBatch2(st, timeline, (byte*)split + (long)used++ * Submit2Size);

            int result = BrovVulkApi.vkQueueSubmit2(queue, used, split, fence);
            self.Settle(st, timeline, result, before);
            return result;
        }

        public static int QueueBindSparse(GenState st, IGuestMemory inst, IntPtr queue, uint count, IntPtr binds, IntPtr fence)
        {
            if (!st.Retire._queues.ContainsKey(queue))
            {
                st.CheckSparseBinds(binds, count);
                return BrovVulkApi.vkQueueBindSparse(queue, count, binds, fence);
            }

            st.MarkDeviceLostOf(st.IdOf(queue, "VkQueue"));
            return BrovVulkConstants.VK_ERROR_DEVICE_LOST;
        }

        private void SignalBatch(GenState st, Timeline timeline, byte* batch) => _signals.Add((_pending, Signal(st, timeline, batch)));

        private void SignalBatch2(GenState st, Timeline timeline, byte* batch) => _signals.Add((_pending, Signal2(st, timeline, batch)));

        private void Settle(GenState st, Timeline timeline, int result, ulong before)
        {
            if (result < 0)
            {
                timeline.Submitted = before;
                return;
            }
            foreach ((int end, ulong value) in _signals)
            {
                _pending = end;
                StampBatch(st, timeline, value);
            }
        }

        private static ulong Signal(GenState st, Timeline timeline, byte* batch)
        {
            ulong value = ++timeline.Submitted;
            new Span<byte>(batch, SubmitSize).Clear();
            *(int*)batch = BrovVulkConstants.VK_STRUCTURE_TYPE_SUBMIT_INFO;
            *(IntPtr*)(batch + SubmitPNext) = TimelineInfo(st, 0, IntPtr.Zero, 1, Values(st, value));
            *(uint*)(batch + SubmitSignalCount) = 1;
            *(IntPtr*)(batch + SubmitSignals) = Handles(st, timeline.Semaphore);
            return value;
        }

        private static ulong Signal2(GenState st, Timeline timeline, byte* batch)
        {
            ulong value = ++timeline.Submitted;
            new Span<byte>(batch, Submit2Size).Clear();
            *(int*)batch = BrovVulkConstants.VK_STRUCTURE_TYPE_SUBMIT_INFO_2;
            *(uint*)(batch + Submit2SignalCount) = 1;
            *(IntPtr*)(batch + Submit2Signals) = SemaphoreInfo(st, timeline, value);
            return value;
        }

        private static void BuildRelay(GenState st, byte* relay, Timeline timeline, ulong value, uint signals, IntPtr guestSignals, uint guestValueCount, IntPtr guestValues)
        {
            new Span<byte>(relay, SubmitSize).Clear();
            *(int*)relay = BrovVulkConstants.VK_STRUCTURE_TYPE_SUBMIT_INFO;
            *(IntPtr*)(relay + SubmitPNext) = TimelineInfo(st, 1, Values(st, value), guestValueCount, guestValues);
            *(uint*)(relay + SubmitWaitCount) = 1;
            *(IntPtr*)(relay + SubmitWaits) = Handles(st, timeline.Semaphore);
            IntPtr stages = st.Alloc(4);
            *(uint*)stages = (uint)BrovVulkConstants.VK_PIPELINE_STAGE_ALL_COMMANDS_BIT;
            *(IntPtr*)(relay + SubmitWaitStages) = stages;
            *(uint*)(relay + SubmitSignalCount) = signals;
            *(IntPtr*)(relay + SubmitSignals) = guestSignals;
        }

        private static IntPtr TimelineInfo(GenState st, uint waitCount, IntPtr waits, uint signalCount, IntPtr signals)
        {
            IntPtr info = st.Alloc(TimelineInfoSize);
            *(int*)info = BrovVulkConstants.VK_STRUCTURE_TYPE_TIMELINE_SEMAPHORE_SUBMIT_INFO;
            *(uint*)(info + TimelineWaitCount) = waitCount;
            *(IntPtr*)(info + TimelineWaits) = waits;
            *(uint*)(info + TimelineSignalCount) = signalCount;
            *(IntPtr*)(info + TimelineSignals) = signals;
            return info;
        }

        private static IntPtr SemaphoreInfo(GenState st, Timeline timeline, ulong value)
        {
            IntPtr info = st.Alloc(SemaphoreInfoSize);
            *(int*)info = BrovVulkConstants.VK_STRUCTURE_TYPE_SEMAPHORE_SUBMIT_INFO;
            *(IntPtr*)(info + SemaphoreInfoSemaphore) = timeline.Semaphore;
            *(ulong*)(info + SemaphoreInfoValue) = value;
            *(ulong*)(info + SemaphoreInfoStages) = (ulong)BrovVulkConstants.VK_PIPELINE_STAGE_2_ALL_COMMANDS_BIT;
            return info;
        }

        private static IntPtr Values(GenState st, ulong value)
        {
            IntPtr values = st.Alloc(8);
            *(ulong*)values = value;
            return values;
        }

        private static IntPtr Handles(GenState st, IntPtr handle)
        {
            IntPtr handles = st.Alloc(8);
            *(IntPtr*)handles = handle;
            return handles;
        }

        private void CollectBatches(GenState st, uint count, IntPtr submits, int submitSize, int listOffset, int countOffset, int stride, int handleOffset)
        {
            _submitted.Clear();
            _batchEnds.Clear();
            _signals.Clear();
            _stamped = _pending = 0;
            for (uint i = 0; submits != IntPtr.Zero && i < count; i++)
            {
                byte* submit = (byte*)submits + (long)i * submitSize;
                byte* list = *(byte**)(submit + listOffset);
                uint buffers = *(uint*)(submit + countOffset);
                st.BeginSubmitBatch();
                for (uint k = 0; list != null && k < buffers; k++)
                    st.CollectSubmitted(*(IntPtr*)(list + (long)k * stride + handleOffset), _submitted);
                _batchEnds.Add(_submitted.Count);
            }
        }

        private void StampBatch(GenState st, Timeline timeline, ulong value)
        {
            for (; _stamped < _pending; _stamped++)
            {
                if (!st.TryGetRecording(_submitted[_stamped], out GenState.Recording? record))
                    continue;

                record.Stamp = record.Stamp.Then(timeline, value);
                if (record.Pool != IntPtr.Zero)
                    StampPool(record.Pool, timeline, value);
                if (record.UsedPools == null)
                    continue;
                foreach (IntPtr pool in record.UsedPools)
                    StampPool(pool, timeline, value);
            }
        }

        private void StampPool(IntPtr pool, Timeline timeline, ulong value)
        {
            ref Stamp stamp = ref CollectionsMarshal.GetValueRefOrAddDefault(_poolStamps, pool, out _);
            stamp = stamp.Then(timeline, value);
        }

        public bool CommandBufferIdle(GenState st, IntPtr buffer)
        {
            if (!st.TryGetRecording(buffer, out GenState.Recording? record) || record.Stamp.Reached)
                return true;

            Refresh();
            return record.Stamp.Reached;
        }

        public bool CommandPoolIdle(GenState st, IntPtr pool)
        {
            if (!st.StandIns.CommandPools.TryGetValue(pool, out CommandPoolRecord? record))
                return true;

            foreach (IntPtr buffer in record.Buffers)
            {
                if (!CommandBufferIdle(st, buffer))
                    return false;
            }

            return true;
        }

        public bool PoolIdle(IntPtr pool)
        {
            if (!_poolStamps.TryGetValue(pool, out Stamp stamp) || stamp.Reached)
                return true;

            Refresh();
            return stamp.Reached;
        }

        // Reset frees the pool's sets, so queued frees would free them twice.
        public void DropSetFrees(IntPtr pool)
        {
            for (int i = 0; i < _entries.Count; i++)
            {
                if (_entries[i].Kind == Kind.FreeDescriptorSets && _entries[i].Handle == pool)
                    Dequeue(i--);
            }
        }

        public void ForgetObject(IntPtr handle, string type)
        {
            if (type == "VkDescriptorPool" || type == "VkQueryPool" || type == "VkCommandPool")
            {
                _poolStamps.Remove(handle);
            }
        }

        private bool HasRoom(GenState st)
        {
            if (_entries.Count < MemoryBudget.VulkanRetiredReleases)
                return true;

            Poll(st);
            return _entries.Count < MemoryBudget.VulkanRetiredReleases;
        }

        public bool TryDefer(uint command, string type, IntPtr device, IntPtr handle)
        {
            return handle != IntPtr.Zero && IsCpu(device)
                && TryAdd(device, new Entry { Kind = Kind.Destroy, Command = command, Type = type, Parent = device, Handle = handle, Owner = handle, OwnerType = type });
        }

        // A surface must outlive any swapchain that holds it.
        public bool TryDeferHeld(uint command, string type, IntPtr parent, IntPtr handle)
        {
            return handle != IntPtr.Zero && _holds.TryGetValue((handle, type), out List<(IntPtr Device, int Count)>? held)
                && TryAdd(held[0].Device, new Entry { Kind = Kind.Destroy, Command = command, Type = type, Parent = parent, Handle = handle, Owner = handle, OwnerType = type });
        }

        public void Hold(IntPtr device, IntPtr ptr, string type)
        {
            if (!_holds.TryGetValue((ptr, type), out List<(IntPtr Device, int Count)>? held))
            {
                held = new List<(IntPtr, int)>(1);
                _holds[(ptr, type)] = held;
            }
            for (int i = 0; i < held.Count; i++)
            {
                if (held[i].Device == device)
                {
                    held[i] = (device, held[i].Count + 1);
                    return;
                }
            }
            held.Add((device, 1));
        }

        private bool IsHeld(IntPtr ptr, string? type) => type != null && _holds.Count != 0 && _holds.ContainsKey((ptr, type));

        public void Unhold(IntPtr device, IntPtr holder, string? holderType, (IntPtr Ptr, string Type)[] objects)
        {
            if (objects.Length != 0 && !TryAdd(device, new Entry { Kind = Kind.Unhold, Parent = device, Owner = holder, OwnerType = holderType, Held = objects }))
                Release(device, objects);
        }

        private void Release(IntPtr device, (IntPtr Ptr, string Type)[] objects)
        {
            foreach ((IntPtr Ptr, string Type) obj in objects)
            {
                if (!_holds.TryGetValue(obj, out List<(IntPtr Device, int Count)>? held))
                    continue;
                for (int i = 0; i < held.Count; i++)
                {
                    if (held[i].Device != device)
                        continue;
                    if (held[i].Count > 1)
                        held[i] = (device, held[i].Count - 1);
                    else
                        held.RemoveAt(i);
                    break;
                }
                if (held.Count == 0)
                    Unpark(obj);
            }
        }

        private void Unpark((IntPtr Ptr, string Type) obj)
        {
            _holds.Remove(obj);
            if (!_parked.Remove(obj, out List<Entry>? waiting))
                return;
            foreach (Entry entry in waiting)
                Enqueue(entry);
        }

        public bool TryDeferDevice(uint command, IntPtr device)
        {
            if (!_devices.TryGetValue(device, out DeviceRecord? record))
                return false;

            Refresh();
            Enqueue(new Entry { Device = record, Targets = Targets(record), Kind = Kind.DestroyDevice, Command = command, Type = "VkDevice", Handle = device });
            return true;
        }

        public bool TryDeferInstance(uint command, IntPtr instance)
        {
            if (!Active)
                return false;

            Enqueue(new Entry { Kind = Kind.DestroyInstance, Command = command, Type = "VkInstance", Handle = instance });
            return true;
        }

        public bool TryDeferFreeMemory(IntPtr device, IntPtr memory)
        {
            return IsCpu(device) && TryAdd(device, new Entry { Kind = Kind.FreeMemory, Parent = device, Handle = memory, Owner = memory, OwnerType = "VkDeviceMemory" });
        }

        public void NoteImport(uint memoryId, IntPtr device)
        {
            if (IsCpu(device))
                _importDevices[memoryId] = device;
        }

        public bool TryDeferUnpin(uint memoryId, IGuestMemory memory, IntPtr pin, IntPtr owner, string? ownerType)
        {
            return _importDevices.Remove(memoryId, out IntPtr device)
                && TryAdd(device, new Entry { Kind = Kind.Unpin, Memory = memory, Handle = pin, Owner = owner, OwnerType = ownerType });
        }

        public bool TryDeferRetained(IntPtr device, (IntPtr[] Blocks, long Bytes) retained, IntPtr owner, string? ownerType)
        {
            return IsCpu(device) && TryAdd(device, new Entry { Kind = Kind.Retained, Retained = retained, Owner = owner, OwnerType = ownerType });
        }

        public static void FreeCommandBuffers(GenState st, IGuestMemory inst, IntPtr device, IntPtr pool, uint count, IntPtr buffers)
        {
            if (count == 0 || buffers == IntPtr.Zero || !st.Retire.IsCpu(device)
                || !st.Retire.TryAdd(device, new Entry { Kind = Kind.FreeCommandBuffers, Parent = device, Handle = pool, Handles = Copy(buffers, count) }))
                BrovVulkApi.vkFreeCommandBuffers(device, pool, count, buffers);
        }

        public static int FreeDescriptorSets(GenState st, IGuestMemory inst, IntPtr device, IntPtr pool, uint count, IntPtr sets)
        {
            if (count != 0 && sets != IntPtr.Zero && st.Retire.IsCpu(device)
                && st.Retire.TryAdd(device, new Entry { Kind = Kind.FreeDescriptorSets, Parent = device, Handle = pool, Handles = Copy(sets, count) }))
                return BrovVulkConstants.VK_SUCCESS;

            return BrovVulkApi.vkFreeDescriptorSets(device, pool, count, sets);
        }

        private static IntPtr[] Copy(IntPtr handles, uint count) => new ReadOnlySpan<IntPtr>((void*)handles, checked((int)count)).ToArray();

        private bool TryAdd(IntPtr device, Entry entry)
        {
            if (_devices.Count == 0 || !_devices.TryGetValue(device, out DeviceRecord? record))
                return false;

            Refresh();
            if (Idle(record) && record.Queued == 0 && !IsHeld(entry.Owner, entry.OwnerType))
                return false;

            // Mark the device lost to stop new work while live objects retire.
            if (_entries.Count >= MemoryBudget.VulkanRetiredReleases && !_overflowed.Contains(device))
            {
                _overflowed.Add(device);
                if (!_overflowLogged)
                {
                    _overflowLogged = true;
                    Utils.LogError($"[!] BrovVulk(gen): releases waiting for a CPU device reached {MemoryBudget.VulkanRetiredReleases}; the device is lost.");
                }
            }

            entry.Device = record;
            entry.Targets = Targets(record);
            Enqueue(entry);
            return true;
        }

        private void Enqueue(Entry entry)
        {
            _entries.Add(entry);
            if (entry.Device != null)
                entry.Device.Queued++;
        }

        private Entry Dequeue(int index)
        {
            Entry entry = _entries[index];
            _entries.RemoveAt(index);
            if (entry.Device != null)
                entry.Device.Queued--;
            return entry;
        }

        private static bool Idle(DeviceRecord record)
        {
            foreach ((IntPtr _, Timeline timeline) in record.Queues)
            {
                if (timeline.Completed < timeline.Submitted)
                    return false;
            }
            return true;
        }

        private static ulong[] Targets(DeviceRecord record)
        {
            ulong[] targets = new ulong[record.Queues.Count];
            for (int i = 0; i < targets.Length; i++)
                targets[i] = record.Queues[i].Timeline.Submitted;
            return targets;
        }

        private static bool Reached(DeviceRecord record, ulong[] targets)
        {
            for (int i = 0; i < targets.Length && i < record.Queues.Count; i++)
            {
                if (record.Queues[i].Timeline.Completed < targets[i])
                    return false;
            }
            return true;
        }

        private void Refresh()
        {
            foreach (DeviceRecord record in _devices.Values)
            {
                foreach ((IntPtr _, Timeline timeline) in record.Queues)
                {
                    if (timeline.Completed >= timeline.Submitted)
                        continue;

                    ulong value = 0;
                    if (BrovVulkApi.vkGetSemaphoreCounterValue(record.Device, timeline.Semaphore, (IntPtr)(&value)) >= 0 && value > timeline.Completed)
                        timeline.Completed = value;
                }
            }
        }

        // Keep release order within each device and retire prior devices before the instance.
        public void Poll(GenState st)
        {
            foreach (IntPtr device in _overflowed)
                st.MarkDeviceLostOf(st.IdOf(device, "VkDevice"));
            _overflowed.Clear();

            Refresh();
            for (int i = 0; i < _entries.Count; i++)
            {
                Entry entry = _entries[i];
                bool due = entry.Device == null ? i == 0 : Reached(entry.Device, entry.Targets);
                if (!due)
                {
                    if (entry.Device != null)
                        SkipDevice(entry.Device, ref i);
                    continue;
                }

                Dequeue(i--);
                if (IsHeld(entry.Owner, entry.OwnerType))
                {
                    if (!_parked.TryGetValue((entry.Owner, entry.OwnerType!), out List<Entry>? waiting))
                    {
                        waiting = new List<Entry>();
                        _parked[(entry.Owner, entry.OwnerType!)] = waiting;
                    }
                    waiting.Add(entry);
                    continue;
                }
                Run(st, entry);
            }
        }

        private void SkipDevice(DeviceRecord record, ref int i)
        {
            while (i + 1 < _entries.Count && _entries[i + 1].Device == record)
                i++;
        }

        private void Run(GenState st, Entry entry)
        {
            IntPtr device = entry.Device?.Device ?? IntPtr.Zero;
            switch (entry.Kind)
            {
                case Kind.Destroy:
                    if (!st.Waits.TryDeferDestroy(entry.Command, entry.Type, entry.Parent, entry.Handle))
                        BrovVulkGenDispatch.RunDeferredDestroy(entry.Command, entry.Parent, entry.Handle);
                    break;
                case Kind.DestroyDevice:
                    RunAllFor(st, entry.Device!);
                    VulkanStandIns.ReleaseHostDevice(st, device);
                    foreach ((IntPtr queue, Timeline _) in entry.Device!.Queues)
                        _queues.Remove(queue);
                    DestroyTimelines(entry.Device!);
                    _devices.Remove(device);
                    if (!st.Waits.TryDeferDestroy(entry.Command, entry.Type, IntPtr.Zero, device))
                        BrovVulkGenDispatch.RunDeferredDestroy(entry.Command, IntPtr.Zero, device);
                    entry.Device!.Addresses?.Dispose();
                    break;
                case Kind.FreeAddress:
                    entry.Device!.Addresses?.Free(entry.AddressBase, entry.AddressSpan, entry.Handle);
                    break;
                case Kind.DestroyInstance:
                    RunParkedChildren(st, entry.Handle);
                    VulkanStandIns.ReleaseHostDevice(st, IntPtr.Zero);
                    if (!st.Waits.TryDeferDestroy(entry.Command, entry.Type, IntPtr.Zero, entry.Handle))
                        BrovVulkGenDispatch.RunDeferredDestroy(entry.Command, IntPtr.Zero, entry.Handle);
                    break;
                case Kind.FreeMemory:
                    BrovVulkApi.vkFreeMemory(device, entry.Handle, IntPtr.Zero);
                    break;
                case Kind.FreeCommandBuffers:
                    fixed (IntPtr* handles = entry.Handles)
                        BrovVulkApi.vkFreeCommandBuffers(device, entry.Handle, (uint)entry.Handles!.Length, (IntPtr)handles);
                    break;
                case Kind.FreeDescriptorSets:
                    fixed (IntPtr* handles = entry.Handles)
                        BrovVulkApi.vkFreeDescriptorSets(device, entry.Handle, (uint)entry.Handles!.Length, (IntPtr)handles);
                    break;
                case Kind.Unpin:
                    entry.Memory!.UnpinBacking(entry.Handle);
                    break;
                case Kind.Retained:
                    st.FreeRetained(entry.Retained);
                    break;
                case Kind.Unhold:
                    Release(device, entry.Held!);
                    break;
            }
        }

        // Late releases for a device must run before its host destroy.
        private void RunAllFor(GenState st, DeviceRecord record)
        {
            List<(IntPtr Ptr, string Type)>? gone = null;
            foreach (KeyValuePair<(IntPtr Ptr, string Type), List<(IntPtr Device, int Count)>> held in _holds)
            {
                held.Value.RemoveAll(share => share.Device == record.Device);
                if (held.Value.Count == 0)
                    (gone ??= new List<(IntPtr, string)>()).Add(held.Key);
            }
            if (gone != null)
            {
                foreach ((IntPtr Ptr, string Type) obj in gone)
                    Unpark(obj);
            }

            for (int i = 0; i < _entries.Count; i++)
            {
                if (_entries[i].Device != record)
                    continue;

                Entry child = Dequeue(i--);
                Run(st, child);
            }
        }

        private void RunParkedChildren(GenState st, IntPtr instance)
        {
            List<Entry>? children = null;
            foreach (List<Entry> waiting in _parked.Values)
            {
                for (int i = 0; i < waiting.Count; i++)
                {
                    if (waiting[i].Kind == Kind.Destroy && waiting[i].Parent == instance)
                    {
                        (children ??= new List<Entry>()).Add(waiting[i]);
                        waiting.RemoveAt(i--);
                    }
                }
            }
            if (children == null)
                return;
            foreach (Entry child in children)
                Run(st, child);
        }


        // Keep backing alive if the driver's queues fail to drain.
        public bool Drain(GenState st, int timeoutMilliseconds)
        {
            long deadline = Environment.TickCount64 + Math.Max(0, timeoutMilliseconds);
            byte* wait = stackalloc byte[WaitInfoSize];
            bool idle = true;
            foreach (DeviceRecord record in _devices.Values)
            {
                foreach ((IntPtr _, Timeline timeline) in record.Queues)
                {
                    if (timeline.Completed >= timeline.Submitted)
                        continue;

                    IntPtr semaphore = timeline.Semaphore;
                    ulong value = timeline.Submitted;
                    new Span<byte>(wait, WaitInfoSize).Clear();
                    *(int*)wait = BrovVulkConstants.VK_STRUCTURE_TYPE_SEMAPHORE_WAIT_INFO;
                    *(uint*)(wait + WaitInfoCount) = 1;
                    *(IntPtr*)(wait + WaitInfoSemaphores) = (IntPtr)(&semaphore);
                    *(IntPtr*)(wait + WaitInfoValues) = (IntPtr)(&value);
                    ulong left = (ulong)Math.Max(0, deadline - Environment.TickCount64) * 1_000_000ul;
                    if (BrovVulkApi.vkWaitSemaphores(record.Device, (IntPtr)wait, left) != BrovVulkConstants.VK_SUCCESS)
                        idle = false;
                }
            }

            if (!idle)
            {
                Utils.LogError("[BrovVulk] a CPU device did not finish its work before dispose; what it reads stays allocated.");
                return false;
            }

            Refresh();
            foreach (List<Entry> waiting in _parked.Values)
            {
                foreach (Entry entry in waiting)
                    Enqueue(entry);
            }
            _parked.Clear();
            _holds.Clear();
            while (_entries.Count != 0)
                Run(st, Dequeue(0));
            foreach (DeviceRecord record in _devices.Values)
                record.Addresses?.Dispose();
            return true;
        }
    }
}
