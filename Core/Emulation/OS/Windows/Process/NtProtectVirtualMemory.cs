using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtProtectVirtualMemory : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
                ulong BaseAddressPtr = Instance.WinHelper.GetArg64(1);
                ulong RegionSizePtr = Instance.WinHelper.GetArg64(2);
                ulong NewProtection = Instance.WinHelper.GetArg64(3);
                ulong OldProtectionPtr = Instance.WinHelper.GetArg64(4);

                // current process
                if (ProcessHandle == ulong.MaxValue)
                {
                    if (BaseAddressPtr == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (!Instance.IsRegionMapped(BaseAddressPtr, sizeof(ulong)))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!Instance.IsRegionMapped(RegionSizePtr, sizeof(ulong)))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    ulong BaseAddress = Instance.ReadMemoryULong(BaseAddressPtr);
                    ulong RegionSize = Instance.ReadMemoryULong(RegionSizePtr);

                    if (BaseAddress == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (RegionSize == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    if (Instance.IsRegionFreed(BaseAddress, true))
                        return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

                    // align requested range to page granularity
                    if (RegionSize == 0)
                        return NTSTATUS.STATUS_INVALID_PARAMETER;

                    ulong PageSize = 0x1000;
                    ulong AlignedBase = BaseAddress & ~0xFFFUL;
                    ulong AlignedEnd = (BaseAddress + RegionSize + 0xFFFUL) & ~0xFFFUL;
                    ulong AlignedSize = AlignedEnd - AlignedBase;

                    if (!Instance.IsMemoryRangeMapped(AlignedBase, AlignedSize))
                        return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

                    // old protection is the protection of the first page of the range
                    if (!Instance.TryFindMemoryRegion(BaseAddress, out MemoryRegion OldRegion))
                        return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

                    MemoryProtection OldProt = OldRegion.Protections;

                    if (OldProtectionPtr != 0 && !Instance.IsRegionMapped(OldProtectionPtr, sizeof(ulong)))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    const ulong PAGE_NOACCESS = 0x01;
                    const ulong PAGE_GUARD = 0x100;
                    ulong BaseProtection = NewProtection & 0xFFUL;

                    if ((NewProtection & PAGE_GUARD) != 0 && BaseProtection == PAGE_NOACCESS)
                        return NTSTATUS.STATUS_INVALID_PAGE_PROTECTION;

                    MemoryProtection NewProt = Instance.WinHelper.ConvertWinProtectToInternal(NewProtection);
                    SpecialProtections NewSpecial = (NewProtection & PAGE_GUARD) != 0 ? SpecialProtections.Guard : SpecialProtections.None;
                    MemoryProtection HostProt = (NewSpecial & SpecialProtections.Guard) != 0 ? MemoryProtection.None : NewProt;

                    if (!Instance._emulator.SetMemoryProtection(AlignedBase, AlignedSize, HostProt))
                        return NTSTATUS.STATUS_INVALID_PAGE_PROTECTION;

                    // rebuild memory region list with splits for the protected range
                    List<MemoryRegion> newRegions = new List<MemoryRegion>();
                    foreach (var r in Instance.EnumerateMemoryRegionsByBase())
                    {
                        ulong rStart = r.BaseAddress;
                        ulong rEnd = r.BaseAddress + r.Size;

                        // no overlap
                        if (rEnd <= AlignedBase || rStart >= AlignedEnd)
                        {
                            newRegions.Add(r);
                            continue;
                        }

                        // left part
                        if (rStart < AlignedBase)
                        {
                            MemoryRegion left = r;
                            left.BaseAddress = rStart;
                            left.Size = AlignedBase - rStart;
                            left.RequestedSize = left.Size;
                            newRegions.Add(left);
                        }

                        // middle part (intersection)
                        ulong midStart = Math.Max(rStart, AlignedBase);
                        ulong midEnd = Math.Min(rEnd, AlignedEnd);
                        MemoryRegion middle = r;
                        middle.BaseAddress = midStart;
                        middle.Size = midEnd - midStart;
                        middle.RequestedSize = middle.Size;
                        middle.Protections = NewProt;
                        middle.Protect = (uint)NewProtection;
                        middle.SpecialProtections = NewSpecial;
                        newRegions.Add(middle);

                        // right part
                        if (rEnd > AlignedEnd)
                        {
                            MemoryRegion right = r;
                            right.BaseAddress = AlignedEnd;
                            right.Size = rEnd - AlignedEnd;
                            right.RequestedSize = right.Size;
                            newRegions.Add(right);
                        }
                    }

                    // merge adjacent regions with identical properties
                    List<MemoryRegion> merged = new List<MemoryRegion>();
                    foreach (var r in newRegions.OrderBy(x => x.BaseAddress))
                    {
                        if (merged.Count == 0)
                        {
                            merged.Add(r);
                            continue;
                        }

                        var last = merged[merged.Count - 1];
                        if (last.BaseAddress + last.Size == r.BaseAddress &&
                            last.AllocationBase == r.AllocationBase &&
                            last.AllocationProtect == r.AllocationProtect &&
                            last.Protect == r.Protect &&
                            last.IsReserved == r.IsReserved &&
                            last.IsCommitted == r.IsCommitted &&
                            last.Protections == r.Protections &&
                            last.InitialProtections == r.InitialProtections &&
                            last.SpecialProtections == r.SpecialProtections &&
                            last.Flags == r.Flags)
                        {
                            last.Size += r.Size;
                            last.RequestedSize = last.Size;
                            merged[merged.Count - 1] = last;
                        }
                        else
                        {
                            merged.Add(r);
                        }
                    }

                    Instance.ReplaceMemoryRegions(merged);

                    if (OldProtectionPtr != 0)
                    {
                        ulong OldWinProt = Instance.WinHelper.ConvertInternalToWinProtect(OldProt);
                        if ((OldRegion.SpecialProtections & SpecialProtections.Guard) != 0)
                            OldWinProt |= 0x100;

                        if (!Instance._emulator.WriteMemory(OldProtectionPtr, OldWinProt))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                    }

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
            else if (Instance._binary.Architecture == BinaryArchitecture.x86)
            {

            }
            return Instance.WinUnimplemented;
        }
    }
}
