using System;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static unsafe class BrovVulkGenMemory
    {
        private const int VkErrorMemoryMapFailed = -5;
        private const int VkStructureTypeMappedMemoryRange = 6;
        private const ulong VkWholeSize = ulong.MaxValue;
        private const ulong MaxMapBytes = 1UL << 30;
        private const uint MaxRanges = 4096;
        private const int RangeStride = 40;
        private const int CopyChunk = 1 << 20;

        internal static int MapMemory(GenReader r, GenState st, BinaryEmulator inst)
        {
            IntPtr device = st.Lookup(r.ReadU32(), "VkDevice");
            uint memId = r.ReadU32();
            IntPtr memory = st.Lookup(memId, "VkDeviceMemory");
            ulong offset = r.ReadU64();
            ulong size = r.ReadU64();
            uint flags = r.ReadU32();
            ulong guestVa = r.ReadU64();
            if (memory == IntPtr.Zero || guestVa == 0 || size == 0 || size > MaxMapBytes || st.HasMapping(memId))
                return VkErrorMemoryMapFailed;
            if (!inst.IsRegionMapped(guestVa, size))
                return VkErrorMemoryMapFailed;
            IntPtr hostPtr = IntPtr.Zero;
            int rr = (int)BrovVulkApi.vkMapMemory(device, memory, offset, size, flags, (IntPtr)(&hostPtr));
            if (rr < 0)
                return rr;
            if (hostPtr == IntPtr.Zero)
            {
                BrovVulkApi.vkUnmapMemory(device, memory);
                return VkErrorMemoryMapFailed;
            }
            CopyHostToGuest(inst, hostPtr, guestVa, size);
            st.AddMapping(memId, hostPtr, guestVa, offset, size);
            return rr;
        }

        internal static int UnmapMemory(GenReader r, GenState st, BinaryEmulator inst)
        {
            IntPtr device = st.Lookup(r.ReadU32(), "VkDevice");
            uint memId = r.ReadU32();
            IntPtr memory = st.Lookup(memId, "VkDeviceMemory");
            if (memory == IntPtr.Zero || !st.TryGetMapping(memId, out GenState.MapEntry e))
                return 0;
            if (inst.IsRegionMapped(e.GuestVa, e.Size))
                CopyGuestToHost(inst, e.GuestVa, e.HostPtr, e.Size);
            BrovVulkApi.vkUnmapMemory(device, memory);
            st.RemoveMapping(memId);
            return 0;
        }

        internal static int FlushMappedMemoryRanges(GenReader r, GenState st, BinaryEmulator inst) =>
            SyncRanges(r, st, inst, invalidate: false);

        internal static int InvalidateMappedMemoryRanges(GenReader r, GenState st, BinaryEmulator inst) =>
            SyncRanges(r, st, inst, invalidate: true);

        internal static void SyncAllMappingsToHost(GenState st, BinaryEmulator inst)
        {
            foreach (GenState.MapEntry e in st.Mappings)
                if (inst.IsRegionMapped(e.GuestVa, e.Size))
                    CopyGuestToHost(inst, e.GuestVa, e.HostPtr, e.Size);
        }

        private static int SyncRanges(GenReader r, GenState st, BinaryEmulator inst, bool invalidate)
        {
            IntPtr device = st.Lookup(r.ReadU32(), "VkDevice");
            uint count = r.ReadU32();
            if (count > MaxRanges)
                throw new InvalidOperationException($"BrovVulk generic: mapped range count {count} exceeds cap.");
            IntPtr ranges = count > 0 ? st.Alloc(BrovVulkGenStruct.CheckedBytes(count, RangeStride)) : IntPtr.Zero;
            IntPtr spans = count > 0 ? st.Alloc(BrovVulkGenStruct.CheckedBytes(count, 24)) : IntPtr.Zero;
            for (uint k = 0; k < count; k++)
            {
                uint memId = r.ReadU32();
                ulong offset = r.ReadU64();
                ulong size = r.ReadU64();
                IntPtr memory = st.Lookup(memId, "VkDeviceMemory");
                if (memory == IntPtr.Zero || !st.TryGetMapping(memId, out GenState.MapEntry e) || offset < e.MapOffset)
                    throw new InvalidOperationException("BrovVulk generic: mapped range outside mapping.");
                ulong rel = offset - e.MapOffset;
                if (rel > e.Size)
                    throw new InvalidOperationException("BrovVulk generic: mapped range outside mapping.");
                ulong len = size == VkWholeSize ? e.Size - rel : size;
                if (len > e.Size - rel)
                    throw new InvalidOperationException("BrovVulk generic: mapped range outside mapping.");
                byte* rp = (byte*)ranges + k * RangeStride;
                *(int*)rp = VkStructureTypeMappedMemoryRange;
                *(IntPtr*)(rp + 16) = memory;
                *(ulong*)(rp + 24) = offset;
                *(ulong*)(rp + 32) = size;
                ulong* sp = (ulong*)((byte*)spans + k * 24);
                sp[0] = (ulong)(long)e.HostPtr + rel;
                sp[1] = e.GuestVa + rel;
                sp[2] = len;
                if (!invalidate && len > 0)
                {
                    EnsureGuestRange(inst, sp[1], len);
                    CopyGuestToHost(inst, sp[1], (IntPtr)(long)sp[0], len);
                }
            }
            int rr = (int)(invalidate
                ? BrovVulkApi.vkInvalidateMappedMemoryRanges(device, count, ranges)
                : BrovVulkApi.vkFlushMappedMemoryRanges(device, count, ranges));
            if (invalidate && rr >= 0)
                for (uint k = 0; k < count; k++)
                {
                    ulong* sp = (ulong*)((byte*)spans + k * 24);
                    if (sp[2] == 0)
                        continue;
                    EnsureGuestRange(inst, sp[1], sp[2]);
                    CopyHostToGuest(inst, (IntPtr)(long)sp[0], sp[1], sp[2]);
                }
            return rr;
        }

        private static void EnsureGuestRange(BinaryEmulator inst, ulong guestVa, ulong size)
        {
            if (!inst.IsRegionMapped(guestVa, size))
                throw new InvalidOperationException("BrovVulk generic: mapped range guest memory not mapped.");
        }

        private static void CopyGuestToHost(BinaryEmulator inst, ulong guestVa, IntPtr hostPtr, ulong size)
        {
            ulong done = 0;
            while (done < size)
            {
                int chunk = (int)Math.Min((ulong)CopyChunk, size - done);
                if (!inst.ReadMemory(guestVa + done, new Span<byte>((byte*)hostPtr + done, chunk)))
                    throw new InvalidOperationException("BrovVulk generic: guest memory read failed.");
                done += (ulong)chunk;
            }
        }

        private static void CopyHostToGuest(BinaryEmulator inst, IntPtr hostPtr, ulong guestVa, ulong size)
        {
            ulong done = 0;
            while (done < size)
            {
                int chunk = (int)Math.Min((ulong)CopyChunk, size - done);
                if (!inst.WriteMemory(guestVa + done, new ReadOnlySpan<byte>((byte*)hostPtr + done, chunk)))
                    throw new InvalidOperationException("BrovVulk generic: guest memory write failed.");
                done += (ulong)chunk;
            }
        }
    }
}
