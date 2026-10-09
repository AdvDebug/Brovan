using System;
using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSetInformationVirtualMemory : IWinSyscall
    {
        private const uint VmPrefetchInformation = 0;
        private const uint VmInformationClassCount = 8;
        private const uint PrefetchFlagsMask = 1;
        private const ulong MaxEntries = 0x0FFFFFFFFFFFFFFFUL;
        private const ulong HighestUserAddress = NtWow64GetNativeSystemInformation.NativeMaximumUserModeAddress;
        private const ulong UserProbeAddress = NtWow64GetNativeSystemInformation.NativeUserProbeAddress;
        private const int ChunkEntries = 256;

        // NT: the WOW64 thunk and the kernel copy the entries, and fail when they cannot allocate the copy.
        private static ulong MaxCopiedEntries => Brovan.Core.Settings.MemoryBudget.PooledIoBytes / 16;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ProcessHandle = Instance.WinHelper.GetArg(0);
            uint InformationClass = (uint)Instance.WinHelper.GetArg(1);
            ulong EntryCount = Instance.WinHelper.GetArg(2);
            ulong EntriesPtr = Instance.WinHelper.GetArg(3);
            ulong InformationPtr = Instance.WinHelper.GetArg(4);
            uint InformationLength = (uint)Instance.WinHelper.GetArg(5);
            uint EntrySize = (uint)Instance.WinHelper.PointerSize * 2;
            bool InvalidEntry = false;

            // NT: the WOW64 thunk copies the entries before the kernel checks anything.
            if (EntrySize < 16)
            {
                if (EntryCount == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER_3;

                if (EntryCount > MaxCopiedEntries)
                    return NTSTATUS.STATUS_NO_MEMORY;

                if (!TryReadEntries(Instance, EntriesPtr, EntryCount, EntrySize, out InvalidEntry))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if (InformationClass >= VmInformationClassCount)
                return NTSTATUS.STATUS_INVALID_PARAMETER_2;

            if (InformationClass != VmPrefetchInformation)
                return Instance.WinUnimplemented;

            if (InformationPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER_5;

            if (InformationLength != sizeof(uint))
                return NTSTATUS.STATUS_INVALID_PARAMETER_6;

            if (EntryCount - 1 > MaxEntries - 1)
                return NTSTATUS.STATUS_INVALID_PARAMETER_3;

            if (EntrySize == 16)
            {
                if ((EntriesPtr & 3) != 0)
                    return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

                ulong EntriesEnd = EntriesPtr + EntryCount * EntrySize;
                if (EntriesEnd > UserProbeAddress || EntriesEnd < EntriesPtr)
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if ((InformationPtr & 3) != 0)
                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

            if (!NtReadVirtualMemory.IsAccessible(Instance, InformationPtr, sizeof(uint), false) || !Instance.WinHelper.TryReadUInt32(InformationPtr, out uint Flags))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = Instance.WinHelper.ResolveProcessHandle(ProcessHandle, AccessMask.ProcessVMOperation, out _);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (EntrySize == 16)
            {
                if (EntryCount > MaxCopiedEntries)
                    return NTSTATUS.STATUS_INSUFFICIENT_RESOURCES;

                if (!TryReadEntries(Instance, EntriesPtr, EntryCount, EntrySize, out InvalidEntry))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if (InvalidEntry)
                return NTSTATUS.STATUS_INVALID_PARAMETER_4;

            if ((Flags & ~PrefetchFlagsMask) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER_5;

            // Prefetch has no effect the guest can see.
            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: all entries are copied before any is checked, so an unreadable entry wins over an invalid one.
        private static bool TryReadEntries(BinaryEmulator Instance, ulong EntriesPtr, ulong EntryCount, uint EntrySize, out bool Invalid)
        {
            Invalid = false;
            Span<byte> Chunk = stackalloc byte[ChunkEntries * 16];
            ulong TotalPages = 0;

            for (ulong Index = 0; Index < EntryCount;)
            {
                int Count = (int)Math.Min((ulong)ChunkEntries, EntryCount - Index);
                ulong Address = EntriesPtr + Index * EntrySize;
                Span<byte> Data = Chunk.Slice(0, Count * (int)EntrySize);

                if (Address < EntriesPtr || !NtReadVirtualMemory.IsAccessible(Instance, Address, (ulong)Data.Length, false) ||
                    !Instance._emulator.ReadMemory(Address, Data))
                    return false;

                for (int Entry = 0; Entry < Count && !Invalid; Entry++)
                {
                    Span<byte> Raw = Data.Slice(Entry * (int)EntrySize, (int)EntrySize);
                    ulong VirtualAddress = EntrySize == 16 ? BinaryPrimitives.ReadUInt64LittleEndian(Raw) : BinaryPrimitives.ReadUInt32LittleEndian(Raw);
                    ulong NumberOfBytes = EntrySize == 16 ? BinaryPrimitives.ReadUInt64LittleEndian(Raw.Slice(8)) : BinaryPrimitives.ReadUInt32LittleEndian(Raw.Slice(4));

                    ulong Last = VirtualAddress + NumberOfBytes - 1;
                    ulong Pages = ((VirtualAddress & 0xFFF) + NumberOfBytes + 0xFFF) >> 12;
                    Invalid = NumberOfBytes == 0 || Last < VirtualAddress || Last > HighestUserAddress || TotalPages + Pages < TotalPages;
                    TotalPages += Pages;
                }

                Index += (ulong)Count;
            }

            return true;
        }
    }
}
