using System;
using System.Buffers.Binary;
using System.Numerics;
using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAllocateVirtualMemory : IWinSyscall
    {
        private const ulong PageSize = 0x1000;
        private const uint MemCommit = 0x00001000;
        private const uint MemReserve = 0x00002000;
        private const uint MemReplacePlaceholder = 0x00004000;
        private const uint MemReservePlaceholder = 0x00040000;
        private const uint MemReset = 0x00080000;
        private const uint MemTopDown = 0x00100000;
        private const uint MemResetUndo = 0x01000000;
        private const uint PageNoAccess = 0x01;

        // MEM_COMMIT, MEM_RESERVE, MEM_REPLACE_PLACEHOLDER, MEM_RESERVE_PLACEHOLDER, MEM_RESET, MEM_TOP_DOWN,
        // MEM_WRITE_WATCH, MEM_PHYSICAL, MEM_ROTATE, MEM_RESET_UNDO and MEM_LARGE_PAGES.
        private const uint KnownAllocationTypes = 0x21FC4000 | MemCommit | MemReserve;

        // MEM_WRITE_WATCH, MEM_PHYSICAL, MEM_ROTATE.
        private const uint UnsupportedAllocationTypes = 0x00200000 | 0x00400000 | 0x00800000;
        private const uint MemLargePages = 0x20000000;

        internal const ulong LowSearchStart = 0x00100000UL;

        internal struct AddressRequirements
        {
            public ulong Lowest;
            public ulong Highest;
            public ulong Alignment;

            public static AddressRequirements None => new AddressRequirements { Highest = ulong.MaxValue };

            public bool Limited => Lowest != 0 || Highest != ulong.MaxValue || Alignment > WinSysHelper.AllocationGranularity;
        }

        private static bool TryApplyResetState(BinaryEmulator Instance, ulong BaseAddress, ulong RegionSize, bool Reset, out NTSTATUS Status)
        {
            Status = NTSTATUS.STATUS_SUCCESS;

            if (BaseAddress == 0 || RegionSize == 0)
            {
                Status = NTSTATUS.STATUS_INVALID_PARAMETER;
                return false;
            }

            if ((BaseAddress & (PageSize - 1)) != 0 || (RegionSize & (PageSize - 1)) != 0)
            {
                Status = NTSTATUS.STATUS_CONFLICTING_ADDRESSES;
                return false;
            }

            ulong End = BaseAddress + RegionSize;
            if (End < BaseAddress)
            {
                Status = NTSTATUS.STATUS_CONFLICTING_ADDRESSES;
                return false;
            }

            Status = Instance.CheckSecuredRange(BaseAddress, RegionSize, NTSTATUS.STATUS_SECTION_PROTECTION);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return false;

            ulong Current = BaseAddress;
            ulong AllocationBase = 0;
            bool HasAllocationBase = false;

            while (Current < End)
            {
                if (!Instance.TryFindMemoryRegionIndex(Current, out int Index) || !Instance.TryFindMemoryRegion(Current, out MemoryRegion Region))
                {
                    Status = NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;
                    return false;
                }

                if (Region.IsPlaceholder)
                {
                    Status = NTSTATUS.STATUS_CONFLICTING_ADDRESSES;
                    return false;
                }

                if (!Region.IsReserved || !Region.IsCommitted)
                {
                    Status = NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;
                    return false;
                }

                if (!HasAllocationBase)
                {
                    AllocationBase = Region.AllocationBase;
                    HasAllocationBase = true;
                }
                else if (Region.AllocationBase != AllocationBase)
                {
                    Status = NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;
                    return false;
                }

                ulong RegionEnd = Region.BaseAddress + Region.Size;
                if (RegionEnd <= Current)
                {
                    Status = NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;
                    return false;
                }

                if (Region.IsReset != Reset)
                {
                    Region.IsReset = Reset;
                    Instance.SetMemoryRegion(Index, Region);
                }

                Current = Math.Min(RegionEnd, End);
            }

            return true;
        }

        // NT: ZeroBits up to 20 counts clear high bits of a 32-bit address, above 32 it is an address mask.
        internal static bool TryGetZeroBitsLimit(ulong ZeroBits, out ulong Highest)
        {
            Highest = ulong.MaxValue;
            if (ZeroBits == 0)
                return true;

            if (ZeroBits <= 20)
            {
                Highest = 0xFFFFFFFFUL >> (int)ZeroBits;
                return true;
            }

            if (ZeroBits <= 32)
                return false;

            int TopBit = 63 - BitOperations.LeadingZeroCount(ZeroBits);
            Highest = TopBit == 63 ? ulong.MaxValue : (1UL << (TopBit + 1)) - 1;
            return true;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ProcessHandle = Instance.WinHelper.GetArg(0);
            ulong BaseAddressPtr = Instance.WinHelper.GetArg(1);
            ulong ZeroBits = Instance.WinHelper.GetArg(2);
            ulong RegionSizePtr = Instance.WinHelper.GetArg(3);
            uint AllocationType = (uint)Instance.WinHelper.GetArg(4);
            uint Protect = (uint)Instance.WinHelper.GetArg(5);

            if (!TryGetZeroBitsLimit(ZeroBits, out ulong Highest))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            AddressRequirements Requirements = AddressRequirements.None;
            Requirements.Highest = Highest;

            return AllocateCommon(Instance, ProcessHandle, BaseAddressPtr, RegionSizePtr, AllocationType, Protect, Requirements, (uint)Instance.WinHelper.PointerSize, false);
        }

        // NT: placeholders need NtAllocateVirtualMemoryEx and MEM_RESERVE. A new one is bare PAGE_NOACCESS.
        private static bool IsValidPlaceholderRequest(uint AllocationType, uint Protect, bool Extended)
        {
            if ((AllocationType & (MemReservePlaceholder | MemReplacePlaceholder)) == 0)
                return true;

            if (!Extended || (AllocationType & MemReserve) == 0)
                return false;

            if ((AllocationType & MemReservePlaceholder) != 0)
                return (AllocationType & ~(MemReserve | MemReservePlaceholder | MemTopDown)) == 0 && Protect == PageNoAccess;

            return true;
        }

        internal static NTSTATUS AllocateCommon(BinaryEmulator Instance, ulong ProcessHandle, ulong BaseAddressPtr, ulong RegionSizePtr, uint AllocationType, uint Protect, AddressRequirements Requirements, uint OutputWidth, bool Extended)
        {
            if (BaseAddressPtr == 0 || RegionSizePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(BaseAddressPtr, OutputWidth) || !Instance.IsRegionMapped(RegionSizePtr, OutputWidth))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong BaseAddress = Instance.WinHelper.ReadPointer(BaseAddressPtr, OutputWidth);
            ulong RegionSize = Instance.WinHelper.ReadPointer(RegionSizePtr, OutputWidth);

            if (RegionSize == 0 || AllocationType == 0 || (AllocationType & ~KnownAllocationTypes) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!IsValidPlaceholderRequest(AllocationType, Protect, Extended))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if ((AllocationType & UnsupportedAllocationTypes) != 0)
                return NTSTATUS.STATUS_NOT_SUPPORTED;

            // Needs SeLockMemoryPrivilege.
            if ((AllocationType & MemLargePages) != 0)
                return NTSTATUS.STATUS_PRIVILEGE_NOT_HELD;

            bool Reset = (AllocationType & MemReset) != 0;
            bool ResetUndo = (AllocationType & MemResetUndo) != 0;
            if (!Reset && !ResetUndo && (AllocationType & (MemCommit | MemReserve)) == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if ((Reset && ResetUndo) || (Reset && AllocationType != MemReset) || (ResetUndo && AllocationType != MemResetUndo))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Protect == 0)
                return NTSTATUS.STATUS_INVALID_PAGE_PROTECTION;

            NTSTATUS Status = Instance.WinHelper.ResolveProcessHandle(ProcessHandle, AccessMask.ProcessVMOperation, out WinProcess Process);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Process.PID != Instance.WinHelper.PID)
            {
                // NT: a 32-bit caller gets memory it can address, whatever the target's width.
                if (OutputWidth < 8)
                    Requirements.Highest = Math.Min(Requirements.Highest, Instance.MaxAddress);

                return AllocateRemote(Instance, Process, BaseAddressPtr, RegionSizePtr, BaseAddress, RegionSize, AllocationType, Protect, Requirements, OutputWidth);
            }

            if (Reset || ResetUndo)
            {
                ulong ResetRegionSize = BinaryEmulator.AlignUp(RegionSize, PageSize);
                if (!TryApplyResetState(Instance, BaseAddress, ResetRegionSize, Reset, out NTSTATUS ResetStatus))
                    return ResetStatus;

                return WriteOutputs(Instance, BaseAddressPtr, RegionSizePtr, BaseAddress, ResetRegionSize, OutputWidth);
            }

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtAllocateVirtualMemory (BaseAddress: 0x{BaseAddress:X}, RegionSize: {RegionSize}, Type: 0x{AllocationType:X})", LogFlags.Syscall);

            Status = Allocate(Instance, ref BaseAddress, ref RegionSize, AllocationType, Protect, Requirements);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            return WriteOutputs(Instance, BaseAddressPtr, RegionSizePtr, BaseAddress, RegionSize, OutputWidth);
        }

        private static NTSTATUS WriteOutputs(BinaryEmulator Instance, ulong BaseAddressPtr, ulong RegionSizePtr, ulong BaseAddress, ulong RegionSize, uint OutputWidth)
        {
            Span<byte> Value = stackalloc byte[8];

            BinaryPrimitives.WriteUInt64LittleEndian(Value, BaseAddress);
            if (!Instance._emulator.WriteMemory(BaseAddressPtr, Value.Slice(0, (int)OutputWidth)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            BinaryPrimitives.WriteUInt64LittleEndian(Value, RegionSize);
            if (!Instance._emulator.WriteMemory(RegionSizePtr, Value.Slice(0, (int)OutputWidth)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS AllocateRemote(BinaryEmulator Instance, WinProcess Process, ulong BaseAddressPtr, ulong RegionSizePtr, ulong BaseAddress, ulong RegionSize, uint AllocationType, uint Protect, AddressRequirements Requirements, uint OutputWidth)
        {
            if (Process.Remote == null)
                return NTSTATUS.STATUS_INVALID_CID;

            NTSTATUS RemoteStatus = Process.Remote.AllocateMemory(BaseAddress, RegionSize, AllocationType, Protect, Requirements, out ulong GrantedBase, out ulong GrantedSize);
            if (RemoteStatus != NTSTATUS.STATUS_SUCCESS)
                return RemoteStatus;

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] Allocated 0x{GrantedSize:X} bytes in process \"{Process.Name}\" at 0x{GrantedBase:X}.", LogFlags.Syscall);

            return WriteOutputs(Instance, BaseAddressPtr, RegionSizePtr, GrantedBase, GrantedSize, OutputWidth);
        }

        internal static NTSTATUS Allocate(BinaryEmulator Instance, ref ulong BaseAddress, ref ulong RegionSize, uint AllocationType, uint Protect, AddressRequirements Requirements)
        {
            bool Reserve = (AllocationType & MemReserve) != 0;
            bool Commit = (AllocationType & MemCommit) != 0;

            if (RegionSize == 0 || BaseAddress > ulong.MaxValue - RegionSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if ((AllocationType & MemReplacePlaceholder) != 0)
                return ReplacePlaceholder(Instance, ref BaseAddress, ref RegionSize, Commit, Protect);

            if (!Reserve && Commit && BaseAddress == 0)
                Reserve = true;

            if (BaseAddress == 0)
            {
                RegionSize = BinaryEmulator.AlignUp(RegionSize, PageSize);

                ulong Highest = Math.Min(Instance.MaxAddress, Requirements.Highest);
                ulong Lowest = Requirements.Lowest != 0
                    ? Requirements.Lowest
                    : Requirements.Limited || Instance.WinHelper.PointerSize != 8 ? LowSearchStart : 0x0000000100000000UL;
                ulong Alignment = Math.Max(Requirements.Alignment, WinSysHelper.AllocationGranularity);

                // HighestEndingAddress is inclusive, the search end is not.
                if (!Instance.TryFindFreeBaseAddress(RegionSize, Alignment, BinaryEmulator.AlignUp(Lowest, WinSysHelper.AllocationGranularity), Highest + 1, out BaseAddress) ||
                    BaseAddress + RegionSize - 1 > Highest)
                {
                    return Requirements.Limited ? NTSTATUS.STATUS_CONFLICTING_ADDRESSES : NTSTATUS.STATUS_NO_MEMORY;
                }
            }
            else
            {
                ulong RequestedEnd = BinaryEmulator.AlignUp(BaseAddress + RegionSize, PageSize);
                BaseAddress &= ~((Reserve ? WinSysHelper.AllocationGranularity : PageSize) - 1);
                RegionSize = RequestedEnd - BaseAddress;
            }

            if (BaseAddress > Instance.MaxAddress || RegionSize - 1 > Instance.MaxAddress - BaseAddress)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Reserve && (!Instance.TryFindMemoryRegion(BaseAddress, out MemoryRegion Target) || Target.IsPlaceholder))
                return NTSTATUS.STATUS_CONFLICTING_ADDRESSES;

            if (!Reserve)
            {
                NTSTATUS Secured = Instance.CheckSecuredRange(BaseAddress, RegionSize, NTSTATUS.STATUS_INVALID_PAGE_PROTECTION);
                if (Secured != NTSTATUS.STATUS_SUCCESS)
                    return Secured;
            }

            if (Reserve)
            {
                bool Reserved = (AllocationType & MemReservePlaceholder) != 0
                    ? Instance.ReservePlaceholder(BaseAddress, RegionSize)
                    : Instance.ReserveMemory(BaseAddress, RegionSize, Protect);

                if (!Reserved)
                    return NTSTATUS.STATUS_CONFLICTING_ADDRESSES;
            }

            if (Commit && !Instance.CommitMemory(BaseAddress, RegionSize, Protect))
            {
                NTSTATUS Failure = Instance.GetLastError() == BackendError.OutOfMemory
                    ? NTSTATUS.STATUS_COMMITMENT_LIMIT
                    : Reserve ? NTSTATUS.STATUS_NO_MEMORY : NTSTATUS.STATUS_CONFLICTING_ADDRESSES;

                if (Reserve)
                    Instance.ReleaseMemory(BaseAddress);

                return Failure;
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        // NT: the range must be exactly one placeholder, which can start on any page.
        private static NTSTATUS ReplacePlaceholder(BinaryEmulator Instance, ref ulong BaseAddress, ref ulong RegionSize, bool Commit, uint Protect)
        {
            if (BaseAddress == 0)
                return NTSTATUS.STATUS_CONFLICTING_ADDRESSES;

            ulong Start = BaseAddress & ~(PageSize - 1);
            ulong End = BinaryEmulator.AlignUp(BaseAddress + RegionSize, PageSize);
            if (End <= Start || End - 1 > Instance.MaxAddress)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.ReplacePlaceholder(Start, End - Start, Protect))
                return NTSTATUS.STATUS_CONFLICTING_ADDRESSES;

            if (Commit && !Instance.CommitMemory(Start, End - Start, Protect))
            {
                NTSTATUS Failure = Instance.GetLastError() == BackendError.OutOfMemory ? NTSTATUS.STATUS_COMMITMENT_LIMIT : NTSTATUS.STATUS_NO_MEMORY;

                if (!Instance.ConvertToPlaceholder(Start, End))
                    Utils.LogError($"[NtAllocateVirtualMemory] Could not restore the placeholder at 0x{Start:X} after a failed commit.");

                return Failure;
            }

            BaseAddress = Start;
            RegionSize = End - Start;
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
