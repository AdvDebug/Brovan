using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAllocateVirtualMemoryEx : IWinSyscall
    {
        private const ulong PageSize = 0x1000;
        private const ulong AllocationGranularity = 0x10000;

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

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
                ulong BaseAddressPtr = Instance.WinHelper.GetArg64(1);
                ulong RegionSizePtr = Instance.WinHelper.GetArg64(2);
                // AllocationType, PageProtection and ExtendedParameterCount are ULONG (32-bit) in the
                // syscall signature; the caller can leave garbage in the upper 32 bits of the register,
                // so mask to 32 bits. Without this, a real count of 0 with non-zero high bits is read as
                // non-zero and wrongly fails the "count != 0 but pointer == 0" check (INVALID_PARAMETER).
                ulong AllocationTypeValue = (uint)Instance.WinHelper.GetArg64(3);
                ulong ProtectValue = (uint)Instance.WinHelper.GetArg64(4);
                ulong ExtendedParametersPtr = Instance.WinHelper.GetArg64(5);
                ulong ExtendedParameterCount = (uint)Instance.WinHelper.GetArg64(6);

                if (ProtectValue == 0x08 || ProtectValue == 0x80)
                    return NTSTATUS.STATUS_INVALID_PAGE_PROTECTION;

                if (BaseAddressPtr == 0 || RegionSizePtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                ulong RegionSizeRaw = Instance.ReadMemoryULong(RegionSizePtr);
                if (RegionSizeRaw == 0 || AllocationTypeValue == 0 || ProtectValue == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (ExtendedParameterCount != 0 && ExtendedParametersPtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (ExtendedParameterCount == 0 && ExtendedParametersPtr != 0)
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

                ulong RegionSize = BinaryEmulator.AlignUp(RegionSizeRaw, PageSize);
                ulong BaseAddress = Instance.ReadMemoryULong(BaseAddressPtr);

                bool Reserve = (AllocationTypeValue & 0x2000UL) != 0; // MEM_RESERVE
                bool Commit = (AllocationTypeValue & 0x1000UL) != 0;  // MEM_COMMIT

                Instance.TriggerEventMessage($"[+] NtAllocateVirtualMemoryEx (BaseAddress: 0x{BaseAddress:X}, RegionSize: {RegionSize}, Commit: {Commit}, Reserve: {Reserve})", LogFlags.Syscall);

                if (!Reserve && !Commit)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

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

                if (ExtendedParameterCount != 0 && ExtendedParametersPtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (ExtendedParameterCount == 0 && ExtendedParametersPtr != 0)
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
