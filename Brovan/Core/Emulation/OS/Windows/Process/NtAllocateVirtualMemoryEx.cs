using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAllocateVirtualMemoryEx : IWinSyscall
    {
        private const ulong PageSize = 0x1000;
        private const ulong AllocationGranularity = 0x10000;
        private const ulong MemReset = 0x00080000UL;
        private const ulong MemResetUndo = 0x01000000UL;

        private static ulong FindFreeBaseAddress(BinaryEmulator Instance, ulong Size, bool IsX64)
        {
            ulong AlignedSize = BinaryEmulator.AlignUp(Size, PageSize);

            ulong MinAddress = IsX64 ? 0x0000000100000000UL : 0x00100000UL;
            MinAddress = BinaryEmulator.AlignUp(MinAddress, AllocationGranularity);

            if (Instance.TryFindFreeBaseAddress(AlignedSize, AllocationGranularity, MinAddress, Instance.MaxAddress, out ulong Result))
                return Result;

            return 0;
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

                if (Region.IsReset == Reset)
                {
                    Current = Math.Min(RegionEnd, End);
                    continue;
                }

                Region.IsReset = Reset;
                Instance.SetMemoryRegion(Index, Region);
                Current = Math.Min(RegionEnd, End);
            }

            return true;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ProcessHandle = Instance.WinHelper.GetArg(0);
            ulong BaseAddressPtr = Instance.WinHelper.GetArg(1);
            ulong RegionSizePtr = Instance.WinHelper.GetArg(2);
            ulong AllocationTypeValue = (uint)Instance.WinHelper.GetArg(3);
            ulong ProtectValue = (uint)Instance.WinHelper.GetArg(4);
            ulong ExtendedParametersPtr = Instance.WinHelper.GetArg(5);
            ulong ExtendedParameterCount = (uint)Instance.WinHelper.GetArg(6);

            if (BaseAddressPtr == 0 || RegionSizePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong RegionSizeRaw = Instance.WinHelper.ReadPointer(RegionSizePtr);
            if (RegionSizeRaw == 0 || AllocationTypeValue == 0 || ProtectValue == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!HandleManager.IsCurrentProcessPseudoHandle(ProcessHandle))
            {
                if (!Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessVMOperation);
                if (Process == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                if (Instance.WinHelper.IsProtectedStatus(Process.Status))
                    return NTSTATUS.STATUS_ACCESS_DENIED;

                return Instance.WinUnimplemented;
            }

            bool Reset = (AllocationTypeValue & MemReset) != 0;
            bool ResetUndo = (AllocationTypeValue & MemResetUndo) != 0;
            if (Reset || ResetUndo)
            {
                if ((Reset && ResetUndo) || (Reset && AllocationTypeValue != MemReset) || (ResetUndo && AllocationTypeValue != MemResetUndo))
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                ulong BaseAddressReset = Instance.WinHelper.ReadPointer(BaseAddressPtr);
                ulong RegionSizeReset = BinaryEmulator.AlignUp(RegionSizeRaw, PageSize);
                if (!TryApplyResetState(Instance, BaseAddressReset, RegionSizeReset, Reset, out NTSTATUS ResetStatus))
                    return ResetStatus;

                if (!Instance._emulator.WriteMemory(BaseAddressPtr, BaseAddressReset))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (!Instance._emulator.WriteMemory(RegionSizePtr, RegionSizeReset))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong RegionSize = BinaryEmulator.AlignUp(RegionSizeRaw, PageSize);
            ulong BaseAddress = Instance.WinHelper.ReadPointer(BaseAddressPtr);

            bool Reserve = (AllocationTypeValue & 0x2000UL) != 0; // MEM_RESERVE
            bool Commit = (AllocationTypeValue & 0x1000UL) != 0;  // MEM_COMMIT

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtAllocateVirtualMemoryEx (BaseAddress: 0x{BaseAddress:X}, RegionSize: {RegionSize}, Commit: {Commit}, Reserve: {Reserve})", LogFlags.Syscall);

            if (!Reserve && !Commit)
            {
                if ((AllocationTypeValue & 0x00080000UL) != 0 || // MEM_RESET
                    (AllocationTypeValue & 0x01000000UL) != 0) // MEM_RESET_UNDO
                    return Instance.WinUnimplemented;

                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            if (RegionSize == 0 || BaseAddress > ulong.MaxValue - RegionSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Reserve && Commit && BaseAddress == 0)
                Reserve = true;

            if (BaseAddress == 0)
            {
                BaseAddress = FindFreeBaseAddress(Instance, RegionSize, Instance.WinHelper.PointerSize == 8);
                if (BaseAddress == 0)
                    return NTSTATUS.STATUS_NO_MEMORY;
            }
            else
            {
                // The requested range stays covered: the base rounds down, the end rounds up.
                ulong Alignment = Reserve ? AllocationGranularity : PageSize;
                ulong RequestedEnd = BaseAddress + RegionSize;
                BaseAddress &= ~(Alignment - 1);
                RegionSize = BinaryEmulator.AlignUp(RequestedEnd, PageSize) - BaseAddress;
            }

            if (BaseAddress > Instance.MaxAddress || RegionSize - 1 > Instance.MaxAddress - BaseAddress)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Reserve)
            {
                if (!Instance.ReserveMemory(BaseAddress, RegionSize, (uint)ProtectValue))
                    return NTSTATUS.STATUS_CONFLICTING_ADDRESSES;
            }

            if (Commit)
            {
                if (!Instance.CommitMemory(BaseAddress, RegionSize, (uint)ProtectValue))
                    return Reserve ? NTSTATUS.STATUS_NO_MEMORY : NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;
            }

            if (!Instance._emulator.WriteMemory(BaseAddressPtr, BaseAddress))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance._emulator.WriteMemory(RegionSizePtr, RegionSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
