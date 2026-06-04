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

            ulong Candidate = IsX64 ? 0x0000000100000000UL : 0x00100000UL;
            Candidate = BinaryEmulator.AlignUp(Candidate, AllocationGranularity);

            for (int Index = 0; Index < 0x200000; Index++)
            {
                if (!Instance.IsRegionInUse(Candidate, AlignedSize))
                    return Candidate;

                Candidate = BinaryEmulator.AlignUp(Candidate + AllocationGranularity, AllocationGranularity);
            }

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
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
                ulong BaseAddressPtr = Instance.WinHelper.GetArg64(1);
                ulong RegionSizePtr = Instance.WinHelper.GetArg64(2);
                ulong AllocationTypeValue = (uint)Instance.WinHelper.GetArg64(3);
                ulong ProtectValue = (uint)Instance.WinHelper.GetArg64(4);
                ulong ExtendedParametersPtr = Instance.WinHelper.GetArg64(5);
                ulong ExtendedParameterCount = (uint)Instance.WinHelper.GetArg64(6);

                if (BaseAddressPtr == 0 || RegionSizePtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                ulong RegionSizeRaw = Instance.ReadMemoryULong(RegionSizePtr);
                if (RegionSizeRaw == 0 || AllocationTypeValue == 0 || ProtectValue == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (ProcessHandle != ulong.MaxValue)
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

                    ulong BaseAddressReset = Instance.ReadMemoryULong(BaseAddressPtr);
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
                ulong BaseAddress = Instance.ReadMemoryULong(BaseAddressPtr);

                bool Reserve = (AllocationTypeValue & 0x2000UL) != 0; // MEM_RESERVE
                bool Commit = (AllocationTypeValue & 0x1000UL) != 0; // MEM_COMMIT

                Instance.TriggerEventMessage($"[+] NtAllocateVirtualMemoryEx (BaseAddress: 0x{BaseAddress:X}, RegionSize: {RegionSize}, Commit: {Commit}, Reserve: {Reserve})", LogFlags.Syscall);

                if (!Reserve && !Commit)
                {
                    if ((AllocationTypeValue & 0x00080000UL) != 0 || // MEM_RESET
                        (AllocationTypeValue & 0x01000000UL) != 0) // MEM_RESET_UNDO
                        return Instance.WinUnimplemented;

                    return NTSTATUS.STATUS_INVALID_PARAMETER;
                }

                if (!Reserve && Commit && BaseAddress == 0)
                    Reserve = true;

                if (BaseAddress == 0)
                {
                    BaseAddress = FindFreeBaseAddress(Instance, RegionSize, IsX64: true);
                    if (BaseAddress == 0)
                        return NTSTATUS.STATUS_NO_MEMORY;
                }
                else
                {
                    BaseAddress = BinaryEmulator.AlignUp(BaseAddress, Reserve ? AllocationGranularity : PageSize);
                }

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

            if (Instance._binary.Architecture == BinaryArchitecture.x86)
            {
                uint SP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);

                uint ProcessHandle = Instance.ReadMemoryUInt(SP + 4);
                uint BaseAddressPtr = Instance.ReadMemoryUInt(SP + 8);
                uint RegionSizePtr = Instance.ReadMemoryUInt(SP + 12);
                uint AllocationTypeValue = Instance.ReadMemoryUInt(SP + 16);
                uint ProtectValue = Instance.ReadMemoryUInt(SP + 20);
                uint ExtendedParametersPtr = Instance.ReadMemoryUInt(SP + 24);
                uint ExtendedParameterCount = Instance.ReadMemoryUInt(SP + 28);

                if (BaseAddressPtr == 0 || RegionSizePtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                uint RegionSizeRaw32 = Instance.ReadMemoryUInt(RegionSizePtr);
                if (RegionSizeRaw32 == 0 || AllocationTypeValue == 0 || ProtectValue == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (ProcessHandle != uint.MaxValue)
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

                    ulong BaseAddressReset = Instance.ReadMemoryUInt(BaseAddressPtr);
                    ulong RegionSizeReset = BinaryEmulator.AlignUp(RegionSizeRaw32, PageSize);
                    if (!TryApplyResetState(Instance, BaseAddressReset, RegionSizeReset, Reset, out NTSTATUS ResetStatus))
                        return ResetStatus;

                    if (!Instance._emulator.WriteMemory(BaseAddressPtr, (uint)BaseAddressReset))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance._emulator.WriteMemory(RegionSizePtr, (uint)RegionSizeReset))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    return NTSTATUS.STATUS_SUCCESS;
                }

                ulong RegionSize = BinaryEmulator.AlignUp(RegionSizeRaw32, PageSize);
                ulong BaseAddress = Instance.ReadMemoryUInt(BaseAddressPtr);

                bool Reserve = (AllocationTypeValue & 0x2000U) != 0;
                bool Commit = (AllocationTypeValue & 0x1000U) != 0;

                Instance.TriggerEventMessage($"[+] NtAllocateVirtualMemoryEx (BaseAddress: 0x{BaseAddress:X}, RegionSize: {RegionSize}, Commit: {Commit}, Reserve: {Reserve})", LogFlags.Syscall);

                if (!Reserve && !Commit)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Reserve && Commit && BaseAddress == 0)
                    Reserve = true;

                if (BaseAddress == 0)
                {
                    BaseAddress = FindFreeBaseAddress(Instance, RegionSize, IsX64: false);
                    if (BaseAddress == 0)
                        return NTSTATUS.STATUS_NO_MEMORY;
                }
                else
                {
                    BaseAddress = BinaryEmulator.AlignUp(BaseAddress, Reserve ? AllocationGranularity : PageSize);
                }

                if (Reserve)
                {
                    if (!Instance.ReserveMemory(BaseAddress, RegionSize, ProtectValue))
                        return NTSTATUS.STATUS_CONFLICTING_ADDRESSES;
                }

                if (Commit)
                {
                    if (!Instance.CommitMemory(BaseAddress, RegionSize, ProtectValue))
                        return Reserve ? NTSTATUS.STATUS_NO_MEMORY : NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;
                }

                if (!Instance._emulator.WriteMemory(BaseAddressPtr, (uint)BaseAddress))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (!Instance._emulator.WriteMemory(RegionSizePtr, (uint)RegionSize))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            return Instance.WinUnimplemented;
        }
    }
}
