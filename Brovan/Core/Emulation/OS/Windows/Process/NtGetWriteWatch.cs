using System;
using System.Buffers.Binary;
using System.Numerics;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtGetWriteWatch : IWinSyscall
    {
        private const ulong PageSize = 0x1000;
        private const uint WriteWatchFlagReset = 1;
        private const ulong HighestUserAddress = NtWow64GetNativeSystemInformation.NativeMaximumUserModeAddress;
        private const ulong UserProbeAddress = NtWow64GetNativeSystemInformation.NativeUserProbeAddress;
        private const ulong MaxCapacity = 0x1FFFFFFFFFFFFFFFUL;
        private const int BatchEntries = 256;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ProcessHandle = Instance.WinHelper.GetArg(0);
            uint Flags = (uint)Instance.WinHelper.GetArg(1);
            ulong BaseAddress = Instance.WinHelper.GetArg(2);
            ulong RegionSize = Instance.WinHelper.GetArg(3);
            ulong AddressesPtr = Instance.WinHelper.GetArg(4);
            ulong CountPtr = Instance.WinHelper.GetArg(5);
            ulong GranularityPtr = Instance.WinHelper.GetArg(6);
            uint PointerSize = (uint)Instance.WinHelper.PointerSize;

            NTSTATUS Status = PointerSize == 8
                ? CaptureNative(Instance, Flags, BaseAddress, RegionSize, AddressesPtr, CountPtr, GranularityPtr, out ulong Capacity)
                : CaptureWow64(Instance, Flags, AddressesPtr, CountPtr, GranularityPtr, out Capacity);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Status = Instance.WinHelper.ResolveProcessHandle(ProcessHandle, AccessMask.ProcessVMOperation, out WinProcess Process);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            ulong Last = BaseAddress + RegionSize - 1;
            if (BaseAddress > Last)
                return NTSTATUS.STATUS_INVALID_PARAMETER_4;

            if (Process.PID != Instance.WinHelper.PID)
                return Instance.WinUnimplemented;

            if (!Instance.IsWriteWatchRange(BaseAddress, Last))
                return NTSTATUS.STATUS_INVALID_PARAMETER_1;

            // NT: WOW64 writes the count and its whole array back after the kernel call.
            if (PointerSize < 8 && (!NtReadVirtualMemory.IsAccessible(Instance, CountPtr, 4, true) || !NtReadVirtualMemory.IsAccessible(Instance, AddressesPtr, Capacity * 4, true)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            Status = Collect(Instance, BaseAddress & ~(PageSize - 1), (Last & ~(PageSize - 1)) + PageSize, (Flags & WriteWatchFlagReset) != 0, AddressesPtr, Capacity, PointerSize, out ulong Count);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (!Instance.WinHelper.WritePointer(CountPtr, Count) || !Instance._emulator.WriteMemory(GranularityPtr, (uint)PageSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: the probes come before the handle lookup.
        private static NTSTATUS CaptureNative(BinaryEmulator Instance, uint Flags, ulong BaseAddress, ulong RegionSize, ulong AddressesPtr, ulong CountPtr, ulong GranularityPtr, out ulong Capacity)
        {
            Capacity = 0;

            if ((Flags & ~WriteWatchFlagReset) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER_2;

            if (BaseAddress > HighestUserAddress)
                return NTSTATUS.STATUS_INVALID_PARAMETER_3;

            if (UserProbeAddress - BaseAddress < RegionSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER_4;

            if (!TryProbe(Instance, CountPtr, 8, true) || !Instance.WinHelper.TryReadUInt64(CountPtr, out Capacity))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Capacity == 0 || Capacity > MaxCapacity)
                return NTSTATUS.STATUS_INVALID_PARAMETER_5;

            if ((AddressesPtr & 7) != 0)
                return NTSTATUS.STATUS_DATATYPE_MISALIGNMENT;

            if (!TryProbe(Instance, AddressesPtr, Capacity * 8, true) || !TryProbe(Instance, GranularityPtr, 4, true))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: the kernel probes the 64-bit copies that the WOW64 thunk makes, so alignment does not matter.
        // A NULL count or array stays NULL.
        private static NTSTATUS CaptureWow64(BinaryEmulator Instance, uint Flags, ulong AddressesPtr, ulong CountPtr, ulong GranularityPtr, out ulong Capacity)
        {
            Capacity = 0;

            if (CountPtr != 0)
            {
                if (!TryProbe(Instance, CountPtr, 4, false))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Capacity = Instance.ReadMemoryUInt(CountPtr);
                if (Capacity != 0 && AddressesPtr != 0 && !TryProbe(Instance, AddressesPtr, Capacity * 4, false))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if ((Flags & ~WriteWatchFlagReset) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER_2;

            if (CountPtr == 0)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (Capacity == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER_5;

            if (AddressesPtr == 0 || !TryProbe(Instance, GranularityPtr, 4, true))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: a probe touches each page and a write probe rewrites a byte in each, which write watch records.
        private static bool TryProbe(BinaryEmulator Instance, ulong Address, ulong Length, bool Write)
        {
            if (!NtReadVirtualMemory.IsAccessible(Instance, Address, Length, Write))
                return false;

            Span<byte> Byte = stackalloc byte[1];
            for (ulong Page = Address; Page < Address + Length; Page = (Page & ~(PageSize - 1)) + PageSize)
            {
                if (!Instance._emulator.ReadMemory(Page, Byte) || (Write && !Instance._emulator.WriteMemory(Page, Byte)))
                    return false;
            }

            return true;
        }

        // NT: with the reset flag, only the reported pages are reset.
        private static NTSTATUS Collect(BinaryEmulator Instance, ulong Start, ulong End, bool Reset, ulong AddressesPtr, ulong Capacity, uint EntrySize, out ulong Count)
        {
            Count = 0;
            Span<ulong> Written = stackalloc ulong[(int)(BinaryEmulator.WriteWatchChunkPages / 64)];
            Span<byte> Batch = stackalloc byte[BatchEntries * 8];
            int Batched = 0;

            for (ulong Cursor = Start; Count < Capacity && Instance.TryGetNextWriteWatchChunk(ref Cursor, End, out ulong Chunk, out ulong Pages);)
            {
                if (!Instance._emulator.QueryWrites(Chunk, Pages, Written))
                {
                    Utils.LogError($"[NtGetWriteWatch] Could not read the write state of 0x{Pages:X} pages at 0x{Chunk:X}: {Instance._emulator.GetLastError()}.");
                    return NTSTATUS.STATUS_UNSUCCESSFUL;
                }

                int Words = (int)((Pages + 63) / 64);
                for (int Word = 0; Word < Words; Word++)
                {
                    for (ulong Bits = Written[Word]; Bits != 0; Bits &= Bits - 1)
                    {
                        ulong Page = Chunk + ((ulong)Word * 64 + (ulong)BitOperations.TrailingZeroCount(Bits)) * PageSize;
                        if (EntrySize == 8)
                            BinaryPrimitives.WriteUInt64LittleEndian(Batch.Slice(Batched * 8), Page);
                        else
                            BinaryPrimitives.WriteUInt32LittleEndian(Batch.Slice(Batched * 4), (uint)Page);

                        Batched++;
                        Count++;
                        if (Batched == BatchEntries && !Flush(Instance, AddressesPtr, Batch, ref Batched, Count, EntrySize))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;

                        if (Count < Capacity)
                            continue;

                        Written[Word] &= ~(Bits & (Bits - 1));
                        Written.Slice(Word + 1, Words - Word - 1).Clear();
                        Word = Words;
                        break;
                    }
                }

                if (Reset && !Instance._emulator.ResetWrites(Chunk, Pages, Written))
                {
                    Utils.LogError($"[NtGetWriteWatch] Could not reset 0x{Pages:X} pages at 0x{Chunk:X}: {Instance._emulator.GetLastError()}.");
                    return NTSTATUS.STATUS_UNSUCCESSFUL;
                }
            }

            return Flush(Instance, AddressesPtr, Batch, ref Batched, Count, EntrySize)
                ? NTSTATUS.STATUS_SUCCESS
                : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }

        private static bool Flush(BinaryEmulator Instance, ulong AddressesPtr, Span<byte> Batch, ref int Batched, ulong Count, uint EntrySize)
        {
            if (Batched == 0)
                return true;

            ulong First = Count - (ulong)Batched;
            if (!Instance._emulator.WriteMemory(AddressesPtr + First * EntrySize, Batch.Slice(0, Batched * (int)EntrySize)))
                return false;

            Batched = 0;
            return true;
        }
    }
}
