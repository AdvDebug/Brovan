using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtFreeVirtualMemory : IWinSyscall
    {
        private const ulong PageSize = 0x1000;
        private const uint MemCoalescePlaceholders = 0x1;
        private const uint MemPreservePlaceholder = 0x2;
        private const uint MemDecommit = 0x4000;
        private const uint MemRelease = 0x8000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ProcessHandle = Instance.WinHelper.GetArg(0);
            ulong BaseAddressPtr = Instance.WinHelper.GetArg(1);
            ulong RegionSizePtr = Instance.WinHelper.GetArg(2);
            uint FreeType = (uint)Instance.WinHelper.GetArg(3);
            uint Width = (uint)Instance.WinHelper.PointerSize;

            if (BaseAddressPtr == 0 || RegionSizePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(BaseAddressPtr, Width) || !Instance.IsRegionMapped(RegionSizePtr, Width))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            bool Decommit = (FreeType & MemDecommit) != 0;
            bool Release = (FreeType & MemRelease) != 0;
            if (Decommit == Release || (FreeType & ~(MemDecommit | MemRelease | MemCoalescePlaceholders | MemPreservePlaceholder)) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER_4;

            // NT's answer for these flags on a region that is not a placeholder.
            if ((FreeType & (MemCoalescePlaceholders | MemPreservePlaceholder)) != 0)
                return Decommit ? NTSTATUS.STATUS_INVALID_PARAMETER_4 : NTSTATUS.STATUS_INVALID_PARAMETER_3;

            NTSTATUS Status = Instance.WinHelper.ResolveProcessHandle(ProcessHandle, AccessMask.ProcessVMOperation, out WinProcess Process);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            ulong BaseAddress = Instance.WinHelper.ReadPointer(BaseAddressPtr);
            ulong RegionSize = Instance.WinHelper.ReadPointer(RegionSizePtr);

            if (Process.PID != Instance.WinHelper.PID)
            {
                if (Process.Remote == null)
                    return NTSTATUS.STATUS_INVALID_CID;

                Status = Process.Remote.FreeMemory(BaseAddress, RegionSize, FreeType, out BaseAddress, out RegionSize);
            }
            else
            {
                Status = Free(Instance, ref BaseAddress, ref RegionSize, FreeType);
            }

            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (!Instance.WinHelper.WritePointer(BaseAddressPtr, BaseAddress) || !Instance.WinHelper.WritePointer(RegionSizePtr, RegionSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static NTSTATUS Free(BinaryEmulator Instance, ref ulong BaseAddress, ref ulong RegionSize, uint FreeType)
        {
            bool Release = (FreeType & MemRelease) != 0;

            if (BaseAddress == 0)
                return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

            if (BaseAddress > ulong.MaxValue - RegionSize)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            // NT: fails inside any view, SEC_RESERVE included.
            if (Instance.WinHelper.IsSectionViewAddress(BaseAddress))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong Start = BaseAddress & ~(PageSize - 1);
            if (!Instance.TryFindMemoryRegion(Start, out MemoryRegion Region))
            {
                if (Release && Instance.IsRegionFreed(BaseAddress, false) && (Instance.Settings.Flags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage($"[!!] Double-Free detected for the allocated memory that have the base address 0x{BaseAddress:X}.", LogFlags.Issues);
                return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;
            }

            ulong AllocationBase = Region.AllocationBase != 0 ? Region.AllocationBase : Region.BaseAddress;
            ulong AllocationSize = AllocationEnd(Instance, AllocationBase) - AllocationBase;

            if (RegionSize == 0 && Start != AllocationBase)
                return NTSTATUS.STATUS_FREE_VM_NOT_AT_BASE;

            ulong End = RegionSize == 0 ? AllocationBase + AllocationSize : BinaryEmulator.AlignUp(BaseAddress + RegionSize, PageSize);
            if (End <= Start)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (End > AllocationBase + AllocationSize)
                return NTSTATUS.STATUS_UNABLE_TO_FREE_VM;

            if (Release)
            {
                // The region list cannot split an allocation.
                if (Start != AllocationBase || End - Start != AllocationSize)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.ReleaseMemory(AllocationBase) && !Instance.UnmapMemoryRegion(AllocationBase))
                    return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;
            }
            else if (!Instance.DecommitMemory(Start, End - Start))
            {
                // A region mapped whole, not reserved, is unmapped when all of it is decommitted.
                if (!Instance.TryFindMemoryRegionByBase(Start, out _, out MemoryRegion Whole) || BinaryEmulator.AlignUp(Whole.Size, PageSize) != End - Start)
                    return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

                if (!Instance.UnmapMemoryRegion(Start))
                    return NTSTATUS.STATUS_INVALID_PAGE_PROTECTION;
            }

            Instance.WinHelper.ForgetLockedPages(Start, End);

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] NtFreeVirtualMemory (BaseAddress: 0x{Start:X}, RegionSize: 0x{End - Start:X}, Release: {Release})", LogFlags.Syscall);

            BaseAddress = Start;
            RegionSize = End - Start;
            return NTSTATUS.STATUS_SUCCESS;
        }

        private static ulong AllocationEnd(BinaryEmulator Instance, ulong AllocationBase)
        {
            if (!Instance.TryFindMemoryRegionIndex(AllocationBase, out int Index))
                return AllocationBase;

            ulong End = AllocationBase;
            for (int Next = Index; Next < Instance._memory.Count; Next++)
            {
                MemoryRegion Region = Instance._memory[Next];
                ulong RegionAllocationBase = Region.AllocationBase != 0 ? Region.AllocationBase : Region.BaseAddress;
                if (RegionAllocationBase != AllocationBase || Region.BaseAddress != End)
                    break;

                End = Region.BaseAddress + BinaryEmulator.AlignUp(Region.Size, PageSize);
            }

            return End;
        }
    }
}
