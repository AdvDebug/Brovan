using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtLockVirtualMemory : IWinSyscall
    {
        private const uint MapProcess = 1;
        private const uint MapSystem = 2;
        private const ulong PageSize = 0x1000;
        private const uint MemCommit = 0x1000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            return Change(Instance, Instance.WinHelper.GetArg(0), Instance.WinHelper.GetArg(1), Instance.WinHelper.GetArg(2), (uint)Instance.WinHelper.GetArg(3), true);
        }

        // Nothing pages out, so a lock is only a record NtUnlockVirtualMemory checks.
        internal static NTSTATUS Change(BinaryEmulator Instance, ulong ProcessHandle, ulong BaseAddressPtr, ulong NumberOfBytesPtr, uint MapType, bool Lock)
        {
            if (MapType == 0 || (MapType & ~(MapProcess | MapSystem)) != 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            // Needs SeLockMemoryPrivilege.
            if ((MapType & MapSystem) != 0)
                return NTSTATUS.STATUS_PRIVILEGE_NOT_HELD;

            NTSTATUS Status = Instance.WinHelper.ResolveProcessHandle(ProcessHandle, AccessMask.ProcessVMOperation, out WinProcess Process);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Process.PID != Instance.WinHelper.PID)
                return Instance.WinUnimplemented;

            uint PointerSize = (uint)Instance.WinHelper.PointerSize;

            if (BaseAddressPtr == 0 || NumberOfBytesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(BaseAddressPtr, PointerSize) || !Instance.IsRegionMapped(NumberOfBytesPtr, PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong BaseAddress = Instance.WinHelper.ReadPointer(BaseAddressPtr);
            ulong NumberOfBytes = Instance.WinHelper.ReadPointer(NumberOfBytesPtr);

            if (NumberOfBytes == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong AlignedBase = BaseAddress & ~(PageSize - 1UL);
            ulong EndAddress = BaseAddress + NumberOfBytes;
            if (EndAddress < BaseAddress)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong AlignedEnd = (EndAddress + PageSize - 1UL) & ~(PageSize - 1UL);
            if (AlignedEnd < EndAddress || AlignedEnd <= AlignedBase)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong AlignedSize = AlignedEnd - AlignedBase;
            if (!Instance.IsRegionMapped(AlignedBase, AlignedSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            for (ulong Page = AlignedBase; Lock && Page < AlignedEnd;)
            {
                if (NtQueryVirtualMemory.BuildBasicInformation(Instance, Page, out MEMORY_BASIC_INFORMATION Info) != NTSTATUS.STATUS_SUCCESS || Info.State != MemCommit)
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Page += Info.RegionSize;
            }

            Status = Lock
                ? Instance.WinHelper.LockPages(AlignedBase, AlignedEnd)
                : Instance.WinHelper.UnlockPages(AlignedBase, AlignedEnd);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            bool WroteBase = Instance.WinHelper.WritePointer(BaseAddressPtr, AlignedBase);
            bool WroteSize = Instance.WinHelper.WritePointer(NumberOfBytesPtr, AlignedSize);

            return WroteBase && WroteSize ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }
    }
}
