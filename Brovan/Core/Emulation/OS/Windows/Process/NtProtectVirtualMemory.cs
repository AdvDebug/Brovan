using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtProtectVirtualMemory : IWinSyscall
    {
        private const ulong PageSize = 0x1000;
        private const uint PageNoAccess = 0x01;
        private const uint PageGuard = 0x100;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            int PointerSize = Instance.WinHelper.PointerSize;
            ulong ProcessHandle = Instance.WinHelper.GetArg(0);
            ulong BaseAddressPtr = Instance.WinHelper.GetArg(1);
            ulong RegionSizePtr = Instance.WinHelper.GetArg(2);
            uint NewProtection = (uint)Instance.WinHelper.GetArg(3);
            ulong OldProtectionPtr = Instance.WinHelper.GetArg(4);

            if (BaseAddressPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(BaseAddressPtr, (uint)PointerSize) || !Instance.IsRegionMapped(RegionSizePtr, (uint)PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (OldProtectionPtr != 0 && !Instance.IsRegionMapped(OldProtectionPtr, sizeof(uint)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = Instance.WinHelper.ResolveProcessHandle(ProcessHandle, AccessMask.ProcessVMOperation, out WinProcess Process);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            ulong BaseAddress = Instance.WinHelper.ReadPointer(BaseAddressPtr);
            ulong RegionSize = Instance.WinHelper.ReadPointer(RegionSizePtr);
            uint OldProtection;

            if (Process.PID != Instance.WinHelper.PID)
            {
                if (Process.Remote == null)
                    return NTSTATUS.STATUS_INVALID_CID;

                Status = Process.Remote.ProtectMemory(BaseAddress, RegionSize, NewProtection, out BaseAddress, out RegionSize, out OldProtection);
            }
            else
            {
                Status = Protect(Instance, ref BaseAddress, ref RegionSize, NewProtection, out OldProtection);
            }

            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (!Instance.WinHelper.WritePointer(BaseAddressPtr, BaseAddress) || !Instance.WinHelper.WritePointer(RegionSizePtr, RegionSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (OldProtectionPtr != 0 && !Instance.WinHelper.WriteUInt32(OldProtectionPtr, OldProtection))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static NTSTATUS Protect(BinaryEmulator Instance, ref ulong BaseAddress, ref ulong RegionSize, uint NewProtection, out uint OldProtection)
        {
            OldProtection = 0;

            if (BaseAddress == 0 || RegionSize == 0 || BaseAddress > ulong.MaxValue - RegionSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Instance.IsRegionFreed(BaseAddress, true))
                return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

            ulong AlignedBase = BaseAddress & ~(PageSize - 1);
            ulong AlignedEnd = BinaryEmulator.AlignUp(BaseAddress + RegionSize, PageSize);
            if (AlignedEnd <= AlignedBase)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong AlignedSize = AlignedEnd - AlignedBase;

            if (!Instance.IsMemoryRangeMapped(AlignedBase, AlignedSize))
                return Instance.TryFindMemoryRegion(AlignedBase, out _) ? NTSTATUS.STATUS_CONFLICTING_ADDRESSES : NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

            if (!Instance.TryFindMemoryRegion(BaseAddress, out MemoryRegion OldRegion))
                return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

            if ((NewProtection & PageGuard) != 0 && (NewProtection & 0xFF) == PageNoAccess)
                return NTSTATUS.STATUS_INVALID_PAGE_PROTECTION;

            MemoryProtection NewProt = Instance.WinHelper.ConvertWinProtectToInternal(NewProtection);
            SpecialProtections NewSpecial = (NewProtection & PageGuard) != 0 ? SpecialProtections.Guard : SpecialProtections.None;

            if (!Instance.ProtectWinMemoryRange(AlignedBase, AlignedSize, NewProt, NewProtection, NewSpecial))
                return NTSTATUS.STATUS_INVALID_PAGE_PROTECTION;

            OldProtection = NtQueryVirtualMemory.RegionWinProtect(Instance, OldRegion);
            BaseAddress = AlignedBase;
            RegionSize = AlignedSize;

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtProtectVirtualMemory (BaseAddress: 0x{AlignedBase:X}, RegionSize: 0x{AlignedSize:X}, New Protections: {NewProt})", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
