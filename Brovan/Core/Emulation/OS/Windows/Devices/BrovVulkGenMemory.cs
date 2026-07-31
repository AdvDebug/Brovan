using System;
using System.Runtime.InteropServices;
using System.Text;
using Brovan.Core.Helpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static unsafe class BrovVulkGenMemory
    {
        private const int VkErrorMemoryMapFailed = -5;
        private const int VkErrorInitializationFailed = -3;
        private const int VkStructureTypeMappedMemoryRange = 6;
        private const ulong VkWholeSize = ulong.MaxValue;
        private const ulong MaxMapBytes = 1UL << 30;
        private const uint MaxRanges = 4096;
        private const int RangeStride = 40;
        private const int CopyChunk = 1 << 20;

        private const int StImportMemoryHostPointerInfo = 1000178000;
        private const int StMemoryHostPointerProperties = 1000178001;
        private const int StExternalMemoryHostProperties = 1000178002;
        private const int StPhysicalDeviceProperties2 = 1000059001;
        private const uint HandleTypeHostAllocation = 0x80;

        private static readonly IntPtr ExternalMemoryHostExtName = Marshal.StringToHGlobalAnsi("VK_EXT_external_memory_host");

        internal static int CreateDevice(GenReader r, GenBuf w, GenState st, int createInfoSid)
        {
            IntPtr pd = st.Lookup(r.ReadU32(), "VkPhysicalDevice");
            uint hasCi = r.ReadU32();
            if (hasCi == 0)
                return VkErrorInitializationFailed;
            IntPtr ci = BrovVulkGenStruct.Rebuild(createInfoSid, r, st);

            bool importCapable = DeviceSupportsHostImport(pd, st);
            if (importCapable)
            {
                uint extCount = *(uint*)(ci + 48);
                IntPtr extPtr = *(IntPtr*)(ci + 56);
                IntPtr newArr = st.Alloc(BrovVulkGenStruct.CheckedBytes(extCount + 1, 8));
                for (uint k = 0; k < extCount; k++)
                    *(IntPtr*)(newArr + (int)(k * 8)) = *(IntPtr*)(extPtr + (int)(k * 8));
                *(IntPtr*)(newArr + (int)(extCount * 8)) = ExternalMemoryHostExtName;
                *(uint*)(ci + 48) = extCount + 1;
                *(IntPtr*)(ci + 56) = newArr;
            }

            IntPtr device = IntPtr.Zero;
            int rr = (int)BrovVulkApi.vkCreateDevice(pd, ci, IntPtr.Zero, (IntPtr)(&device));
            if (rr >= 0 && device == IntPtr.Zero)
                rr = VkErrorInitializationFailed;
            if (rr < 0)
                return rr;

            if (importCapable)
            {
                IntPtr name = Marshal.StringToHGlobalAnsi("vkGetMemoryHostPointerPropertiesEXT");
                IntPtr fn = BrovVulkApi.vkGetDeviceProcAddr(device, name);
                Marshal.FreeHGlobal(name);
                ulong alignment = QueryImportAlignment(pd, out uint apiVersion);
                if (fn != IntPtr.Zero && alignment != 0 && (alignment & (alignment - 1)) == 0)
                {
                    st.SetDeviceImport(device, new GenState.DeviceImport(fn, alignment));
                    ImportStats.Record(ImportOutcome.DeviceImportReady, alignment);
                }
                else if (fn == IntPtr.Zero)
                    ImportStats.Record(ImportOutcome.DeviceProcAddrMissing, alignment);
                else
                    ImportStats.Record(ImportOutcome.DeviceAlignmentUnusable, apiVersion);
            }
            else
            {
                ImportStats.Record(ImportOutcome.DeviceExtensionAbsent, 0);
            }

            w.WriteU32(st.Register(device, "VkDevice"));
            return rr;
        }

        private static bool DeviceSupportsHostImport(IntPtr pd, GenState st)
        {
            uint count = 0;
            if ((int)BrovVulkApi.vkEnumerateDeviceExtensionProperties(pd, IntPtr.Zero, (IntPtr)(&count), IntPtr.Zero) < 0 || count == 0 || count > 4096)
                return false;
            IntPtr props = st.Alloc(BrovVulkGenStruct.CheckedBytes(count, 260));
            if ((int)BrovVulkApi.vkEnumerateDeviceExtensionProperties(pd, IntPtr.Zero, (IntPtr)(&count), props) < 0)
                return false;
            for (uint k = 0; k < count; k++)
            {
                byte* name = (byte*)props + k * 260;
                if (AnsiEquals(name, "VK_EXT_external_memory_host"))
                    return true;
            }
            return false;
        }

        private static bool AnsiEquals(byte* p, string s)
        {
            int i = 0;
            for (; i < s.Length; i++)
                if (p[i] != (byte)s[i])
                    return false;
            return p[i] == 0;
        }

        private static ulong QueryImportAlignment(IntPtr pd) => QueryImportAlignment(pd, out _);

        private static ulong QueryImportAlignment(IntPtr pd, out uint apiVersion)
        {
            byte* ext = stackalloc byte[24];
            new Span<byte>(ext, 24).Clear();
            *(int*)ext = StExternalMemoryHostProperties;
            byte* props2 = stackalloc byte[848];
            new Span<byte>(props2, 848).Clear();
            *(int*)props2 = StPhysicalDeviceProperties2;
            *(void**)(props2 + 8) = ext;
            BrovVulkApi.vkGetPhysicalDeviceProperties2(pd, (IntPtr)props2);
            apiVersion = *(uint*)(props2 + 16);
            return *(ulong*)(ext + 16);
        }

        internal static int AllocateMemory(GenReader r, GenBuf w, GenState st, BinaryEmulator inst, int allocInfoSid)
        {
            IntPtr device = st.Lookup(r.ReadU32(), "VkDevice");
            uint hasInfo = r.ReadU32();
            if (hasInfo == 0)
                return VkErrorInitializationFailed;
            IntPtr ai = BrovVulkGenStruct.Rebuild(allocInfoSid, r, st);
            ulong bounceVa = r.ReadU64();
            ulong bounceSize = r.ReadU64();

            uint imported = 0;
            IntPtr memory = IntPtr.Zero;
            int rr = -1;

            if (bounceVa == 0 || bounceSize == 0)
            {
                ImportStats.Record(ImportOutcome.NoGuestBounce, 0);
            }
            else if (!st.TryGetDeviceImport(device, out GenState.DeviceImport di))
            {
                ImportStats.Record(ImportOutcome.DeviceLacksHostImport, bounceSize);
            }
            else
            {
                ulong size = *(ulong*)(ai + 16);
                ulong aligned = (size + di.Alignment - 1) & ~(di.Alignment - 1);
                IntPtr host = aligned != 0 && aligned <= bounceSize ? inst.GetHostPointer(bounceVa, aligned) : IntPtr.Zero;

                if (aligned == 0 || aligned > bounceSize)
                    ImportStats.Record(ImportOutcome.BounceTooSmall, size);
                else if (host == IntPtr.Zero)
                    ImportStats.Record(ImportOutcome.GuestRangeNotResolvable, size);
                else if (((ulong)host & (di.Alignment - 1)) != 0)
                    ImportStats.Record(ImportOutcome.HostPointerMisaligned, size);
                else if (!ImportTypeBitsAllow(device, di, host, *(uint*)(ai + 24)))
                    ImportStats.Record(ImportOutcome.MemoryTypeNotImportable, size);
                else
                {
                    byte* import = stackalloc byte[32];
                    new Span<byte>(import, 32).Clear();
                    *(int*)import = StImportMemoryHostPointerInfo;
                    *(void**)(import + 8) = *(void**)(ai + 8);
                    *(uint*)(import + 16) = HandleTypeHostAllocation;
                    *(void**)(import + 24) = (void*)host;
                    void* savedNext = *(void**)(ai + 8);
                    *(void**)(ai + 8) = import;
                    *(ulong*)(ai + 16) = aligned;
                    rr = (int)BrovVulkApi.vkAllocateMemory(device, ai, IntPtr.Zero, (IntPtr)(&memory));
                    if (rr >= 0 && memory != IntPtr.Zero)
                    {
                        imported = 1;
                        ImportStats.Record(ImportOutcome.Imported, size);
                    }
                    else
                    {
                        *(void**)(ai + 8) = savedNext;
                        *(ulong*)(ai + 16) = size;
                        memory = IntPtr.Zero;
                        rr = -1;
                        ImportStats.Record(ImportOutcome.DriverRejectedImport, size);
                    }
                }
            }

            if (imported == 0)
            {
                rr = (int)BrovVulkApi.vkAllocateMemory(device, ai, IntPtr.Zero, (IntPtr)(&memory));
                if (rr >= 0 && memory == IntPtr.Zero)
                    rr = VkErrorInitializationFailed;
            }
            if (rr < 0)
                return rr;

            uint id = st.Register(memory, "VkDeviceMemory");
            if (imported != 0)
                st.MarkImported(id);
            w.WriteU32(id);
            return rr;
        }

        private static bool ImportTypeBitsAllow(IntPtr device, GenState.DeviceImport di, IntPtr host, uint memoryTypeIndex)
        {
            if (memoryTypeIndex >= 32)
                return false;
            byte* props = stackalloc byte[24];
            new Span<byte>(props, 24).Clear();
            *(int*)props = StMemoryHostPointerProperties;
            var fn = (delegate* unmanaged<IntPtr, uint, IntPtr, IntPtr, int>)di.GetHostPointerProps;
            if (fn(device, HandleTypeHostAllocation, host, (IntPtr)props) < 0)
                return false;
            uint bits = *(uint*)(props + 16);
            return (bits & (1u << (int)memoryTypeIndex)) != 0;
        }

        internal static int FreeMemory(GenReader r, GenState st)
        {
            IntPtr device = st.Lookup(r.ReadU32(), "VkDevice");
            uint memId = r.ReadU32();
            if (memId == 0)
                return 0;
            IntPtr memory = st.Lookup(memId, "VkDeviceMemory");
            if (memory == IntPtr.Zero)
                return 0;
            if (st.HasMapping(memId))
            {
                BrovVulkApi.vkUnmapMemory(device, memory);
                st.RemoveMapping(memId);
            }
            BrovVulkApi.vkFreeMemory(device, memory, IntPtr.Zero);
            st.Forget(memId);
            return 0;
        }

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
            bool imported = st.IsImportedMemory(memId);
            IntPtr hostPtr = IntPtr.Zero;
            int rr = (int)BrovVulkApi.vkMapMemory(device, memory, offset, size, flags, (IntPtr)(&hostPtr));
            if (rr < 0)
                return rr;
            if (hostPtr == IntPtr.Zero)
            {
                BrovVulkApi.vkUnmapMemory(device, memory);
                return VkErrorMemoryMapFailed;
            }
            if (!imported)
                CopyHostToGuest(inst, hostPtr, guestVa, size);
            st.AddMapping(memId, hostPtr, guestVa, offset, size, imported);
            return rr;
        }

        internal static int UnmapMemory(GenReader r, GenState st, BinaryEmulator inst)
        {
            IntPtr device = st.Lookup(r.ReadU32(), "VkDevice");
            uint memId = r.ReadU32();
            IntPtr memory = st.Lookup(memId, "VkDeviceMemory");
            if (memory == IntPtr.Zero || !st.TryGetMapping(memId, out GenState.MapEntry e))
                return 0;
            if (!e.Imported && inst.IsRegionMapped(e.GuestVa, e.Size))
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
            int copied = 0;
            ulong bytes = 0;
            foreach (GenState.MapEntry e in st.Mappings)
                if (!e.Imported && inst.IsRegionMapped(e.GuestVa, e.Size))
                {
                    CopyGuestToHost(inst, e.GuestVa, e.HostPtr, e.Size);
                    copied++;
                    bytes += e.Size;
                }

            ImportStats.RecordSync(copied, bytes);
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
                sp[2] = e.Imported ? 0 : len;
                if (!invalidate && !e.Imported && len > 0)
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

        private enum ImportOutcome
        {
            Imported,
            NoGuestBounce,
            DeviceLacksHostImport,
            BounceTooSmall,
            GuestRangeNotResolvable,
            HostPointerMisaligned,
            MemoryTypeNotImportable,
            DriverRejectedImport,
            DeviceImportReady,
            DeviceExtensionAbsent,
            DeviceProcAddrMissing,
            DeviceAlignmentUnusable,
        }

        /// <summary>
        /// Set BROVVULK_IMPORT_STATS=1 to record why host-pointer import falls back to the copy path,
        /// and what the fallback costs per queue submit.
        /// </summary>
        private static class ImportStats
        {
            private const int ReportInterval = 256;

            internal static readonly bool Enabled =
                string.Equals(Environment.GetEnvironmentVariable("BROVVULK_IMPORT_STATS"), "1", StringComparison.Ordinal);

            private static readonly int[] Counts = new int[Enum.GetValues<ImportOutcome>().Length];
            private static readonly ulong[] Bytes = new ulong[Enum.GetValues<ImportOutcome>().Length];

            private static long _syncCalls;
            private static long _syncMappings;
            private static ulong _syncBytes;
            private static int _sinceReport;

            internal static void Record(ImportOutcome outcome, ulong size)
            {
                if (!Enabled)
                    return;

                Counts[(int)outcome]++;
                Bytes[(int)outcome] += size;
                Tick();
            }

            internal static void RecordSync(int mappings, ulong bytes)
            {
                if (!Enabled)
                    return;

                _syncCalls++;
                _syncMappings += mappings;
                _syncBytes += bytes;
                Tick();
            }

            private static void Tick()
            {
                if (++_sinceReport < ReportInterval)
                    return;

                _sinceReport = 0;
                Report();
            }

            private static void Report()
            {
                StringBuilder sb = new StringBuilder("BrovVulk import stats:");
                for (int i = 0; i < Counts.Length; i++)
                {
                    if (Counts[i] == 0)
                        continue;
                    sb.Append(' ').Append((ImportOutcome)i).Append('=').Append(Counts[i]).Append('(');
                    if (Bytes[i] >= 1UL << 20)
                        sb.Append(Bytes[i] >> 20).Append(" MB)");
                    else
                        sb.Append(Bytes[i]).Append("B)");
                }

                sb.Append(" | submits=").Append(_syncCalls)
                  .Append(" mappingsCopied=").Append(_syncMappings)
                  .Append(" copied=").Append(_syncBytes >> 20).Append(" MB");

                if (_syncCalls != 0)
                    sb.Append(" avgPerSubmit=").Append((_syncBytes / (ulong)_syncCalls) >> 10).Append(" KB");

                Utils.LogError(sb.ToString());
                Utils.FlushLog();
            }
        }
    }
}
