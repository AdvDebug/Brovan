using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtFreeVirtualMemory : IWinSyscall
    {
        private const ulong PageSize = 0x1000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            const ulong MemDecommit = 0x4000;
            const ulong MemRelease = 0x8000;

            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong ProcessHandle = Instance.WinHelper.GetArg(0);
                ulong BaseAddressPtr = Instance.WinHelper.GetArg(1);
                ulong RegionSizePtr = Instance.WinHelper.GetArg(2);
                ulong FreeType = (uint)Instance.WinHelper.GetArg(3);

                if (BaseAddressPtr == 0 || RegionSizePtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(BaseAddressPtr, sizeof(ulong)) || !Instance.IsRegionMapped(RegionSizePtr, sizeof(ulong)))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

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

                ulong BaseAddress = Instance.WinHelper.ReadPointer(BaseAddressPtr);
                ulong RegionSize = Instance.WinHelper.ReadPointer(RegionSizePtr);

                bool Decommit = (FreeType & MemDecommit) != 0;
                bool Release = (FreeType & MemRelease) != 0;

                if (Decommit == Release)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (BaseAddress == 0)
                    return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

                if (Release)
                {
                    if (RegionSize != 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (Instance.IsRegionFreed(BaseAddress, false))
                    {
                        if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                            Instance.TriggerEventMessage($"[!!] Double-Free detected for the allocated memory that have the base address 0x{BaseAddress:X}.", LogFlags.Issues);
                        return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;
                    }

                    if (!Instance.ReleaseMemory(BaseAddress))
                    {
                        if (!Instance.UnmapMemoryRegion(BaseAddress))
                            return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;
                    }

                    Instance._emulator.WriteMemory(BaseAddressPtr, 0UL);
                    Instance._emulator.WriteMemory(RegionSizePtr, 0UL);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                if (RegionSize == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                ulong AlignedBase = BaseAddress & ~0xFFFUL;
                ulong AlignedEnd = BinaryEmulator.AlignUp(BaseAddress + RegionSize, PageSize);
                ulong AlignedSize = AlignedEnd - AlignedBase;

                if (!Instance.DecommitMemory(BaseAddress, RegionSize))
                {
                    if (Instance.TryFindMemoryRegionByBase(BaseAddress, out _, out MemoryRegion Region) && BinaryEmulator.AlignUp(Region.Size, PageSize) == AlignedSize)
                        return Instance.UnmapMemoryRegion(BaseAddress) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PAGE_PROTECTION;

                    return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;
                }

                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[+] NtFreeVirtualMemory (BaseAddress: 0x{BaseAddress:X}, RegionSize: {RegionSize}, Release: {Release})", LogFlags.Syscall);

                Instance._emulator.WriteMemory(BaseAddressPtr, AlignedBase);
                Instance._emulator.WriteMemory(RegionSizePtr, AlignedSize);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Instance._binary.Architecture == BinaryArchitecture.x86)
            {

                uint ProcessHandle = (uint)Instance.WinHelper.GetArg(0);
                uint BaseAddressPtr = (uint)Instance.WinHelper.GetArg(1);
                uint RegionSizePtr = (uint)Instance.WinHelper.GetArg(2);
                uint FreeType = (uint)Instance.WinHelper.GetArg(3);

                if (BaseAddressPtr == 0 || RegionSizePtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(BaseAddressPtr, 4) || !Instance.IsRegionMapped(RegionSizePtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

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

                ulong BaseAddress = Instance.ReadMemoryUInt(BaseAddressPtr);
                ulong RegionSize = Instance.ReadMemoryUInt(RegionSizePtr);

                bool Decommit = ((ulong)FreeType & MemDecommit) != 0;
                bool Release = ((ulong)FreeType & MemRelease) != 0;

                if (Decommit == Release)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (BaseAddress == 0)
                    return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

                if (Release)
                {
                    if (RegionSize != 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (Instance.IsRegionFreed(BaseAddress, false))
                    {
                        if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                            Instance.TriggerEventMessage($"[!!] Double-Free detected for the allocated memory that have the base address 0x{BaseAddress:X}.", LogFlags.Issues);
                        return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;
                    }

                    if (!Instance.ReleaseMemory(BaseAddress))
                    {
                        if (!Instance.UnmapMemoryRegion(BaseAddress))
                            return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;
                    }

                    Instance._emulator.WriteMemory(BaseAddressPtr, 0u);
                    Instance._emulator.WriteMemory(RegionSizePtr, 0u);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                if (RegionSize == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                ulong AlignedBase = BaseAddress & ~0xFFFUL;
                ulong AlignedEnd = BinaryEmulator.AlignUp(BaseAddress + RegionSize, PageSize);
                ulong AlignedSize = AlignedEnd - AlignedBase;

                if (!Instance.DecommitMemory(BaseAddress, RegionSize))
                {
                    if (Instance.TryFindMemoryRegionByBase(BaseAddress, out _, out MemoryRegion Region) && BinaryEmulator.AlignUp(Region.Size, PageSize) == AlignedSize)
                        return Instance.UnmapMemoryRegion(BaseAddress) ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_PAGE_PROTECTION;

                    return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;
                }

                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                    Instance.TriggerEventMessage($"[+] NtFreeVirtualMemory (BaseAddress: 0x{BaseAddress:X}, RegionSize: {RegionSize}, Release: {Release})", LogFlags.Syscall);

                Instance._emulator.WriteMemory(BaseAddressPtr, (uint)AlignedBase);
                Instance._emulator.WriteMemory(RegionSizePtr, (uint)AlignedSize);
                return NTSTATUS.STATUS_SUCCESS;
            }

            return Instance.WinUnimplemented;
        }
    }
}
