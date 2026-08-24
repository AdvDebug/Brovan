using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtProtectVirtualMemory : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            {
                int PointerSize = Instance.WinHelper.PointerSize;
                ulong ProcessHandle = Instance.WinHelper.GetArg(0);
                ulong BaseAddressPtr = Instance.WinHelper.GetArg(1);
                ulong RegionSizePtr = Instance.WinHelper.GetArg(2);
                ulong NewProtection = (uint)Instance.WinHelper.GetArg(3);
                ulong OldProtectionPtr = Instance.WinHelper.GetArg(4);

                // current process
                if (Instance.WinHelper.IsCurrentProcessHandle(ProcessHandle, AccessMask.ProcessVMOperation))
                {
                    if (BaseAddressPtr == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (!Instance.IsRegionMapped(BaseAddressPtr, (uint)PointerSize))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance.IsRegionMapped(RegionSizePtr, (uint)PointerSize))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    ulong BaseAddress = Instance.WinHelper.ReadPointer(BaseAddressPtr);
                    ulong RegionSize = Instance.WinHelper.ReadPointer(RegionSizePtr);

                    if (BaseAddress == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (RegionSize == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (Instance.IsRegionFreed(BaseAddress, true))
                        return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

                    // align requested range to page granularity
                    if (RegionSize == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    ulong AlignedBase = BaseAddress & ~0xFFFUL;
                    ulong AlignedEnd = (BaseAddress + RegionSize + 0xFFFUL) & ~0xFFFUL;
                    ulong AlignedSize = AlignedEnd - AlignedBase;

                    if (!Instance.IsMemoryRangeMapped(AlignedBase, AlignedSize))
                        return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

                    // old protection is the protection of the first page of the range
                    if (!Instance.TryFindMemoryRegion(BaseAddress, out MemoryRegion OldRegion))
                        return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

                    MemoryProtection OldProt = OldRegion.Protections;

                    if (OldProtectionPtr != 0 && !Instance.IsRegionMapped(OldProtectionPtr, sizeof(uint)))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    const ulong PAGE_NOACCESS = 0x01;
                    const ulong PAGE_GUARD = 0x100;
                    ulong BaseProtection = NewProtection & 0xFFUL;

                    if ((NewProtection & PAGE_GUARD) != 0 && BaseProtection == PAGE_NOACCESS)
                        return NTSTATUS.STATUS_INVALID_PAGE_PROTECTION;

                    MemoryProtection NewProt = Instance.WinHelper.ConvertWinProtectToInternal(NewProtection);
                    SpecialProtections NewSpecial = (NewProtection & PAGE_GUARD) != 0 ? SpecialProtections.Guard : SpecialProtections.None;

                    if (!Instance.ProtectWinMemoryRange(AlignedBase, AlignedSize, NewProt, (uint)NewProtection, NewSpecial))
                        return NTSTATUS.STATUS_INVALID_PAGE_PROTECTION;

                    if (OldProtectionPtr != 0)
                    {
                        ulong OldWinProt = Instance.WinHelper.ConvertInternalToWinProtect(OldProt);
                        if ((OldRegion.SpecialProtections & SpecialProtections.Guard) != 0)
                            OldWinProt |= 0x100;

                        if (!Instance.WinHelper.WriteUInt32(OldProtectionPtr, (uint)OldWinProt))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

                    if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                        Instance.TriggerEventMessage($"[+] NtProtectVirtualMemory (BaseAddress: 0x{BaseAddress:X}, RegionSize: {RegionSize}, New Protections: {NewProt})", LogFlags.Syscall);

                    return NTSTATUS.STATUS_SUCCESS;
                }
                else
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
            }
        }
    }
}
