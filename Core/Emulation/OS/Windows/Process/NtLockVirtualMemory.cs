using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtLockVirtualMemory : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
                return Handle64(Instance);

            return Handle32(Instance);
        }

        private static NTSTATUS Handle64(BinaryEmulator Instance)
        {
            ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
            ulong BaseAddressPtr = Instance.WinHelper.GetArg64(1);
            ulong NumberOfBytesToLockPtr = Instance.WinHelper.GetArg64(2);
            uint MapType = (uint)Instance.WinHelper.GetArg64(3);

            return HandleCommon(Instance, ProcessHandle, BaseAddressPtr, NumberOfBytesToLockPtr, MapType, 8);
        }

        private static NTSTATUS Handle32(BinaryEmulator Instance)
        {
            uint SP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);
            ulong ProcessHandle = Instance.ReadMemoryUInt(SP + 4);
            ulong BaseAddressPtr = Instance.ReadMemoryUInt(SP + 8);
            ulong NumberOfBytesToLockPtr = Instance.ReadMemoryUInt(SP + 12);
            uint MapType = Instance.ReadMemoryUInt(SP + 16);

            return HandleCommon(Instance, ProcessHandle, BaseAddressPtr, NumberOfBytesToLockPtr, MapType, 4);
        }

        private static NTSTATUS HandleCommon(BinaryEmulator Instance, ulong ProcessHandle, ulong BaseAddressPtr, ulong NumberOfBytesToLockPtr, uint MapType, uint PointerSize)
        {
            if (!Instance.WinHelper.IsCurrentProcessHandle(ProcessHandle, AccessMask.ProcessVMOperation))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (BaseAddressPtr == 0 || NumberOfBytesToLockPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(BaseAddressPtr, PointerSize) || !Instance.IsRegionMapped(NumberOfBytesToLockPtr, PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong BaseAddress = PointerSize == 8
                ? Instance.ReadMemoryULong(BaseAddressPtr)
                : Instance.ReadMemoryUInt(BaseAddressPtr);
            ulong NumberOfBytesToLock = PointerSize == 8
                ? Instance.ReadMemoryULong(NumberOfBytesToLockPtr)
                : Instance.ReadMemoryUInt(NumberOfBytesToLockPtr);

            if (NumberOfBytesToLock == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            const ulong PageSize = 0x1000;
            ulong AlignedBase = BaseAddress & ~(PageSize - 1UL);
            ulong EndAddress = BaseAddress + NumberOfBytesToLock;
            if (EndAddress < BaseAddress)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong AlignedEnd = (EndAddress + PageSize - 1UL) & ~(PageSize - 1UL);
            if (AlignedEnd < EndAddress || AlignedEnd <= AlignedBase)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            ulong AlignedSize = AlignedEnd - AlignedBase;
            if (!Instance.IsRegionMapped(AlignedBase, AlignedSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            bool WroteBase = PointerSize == 8
                ? Instance._emulator.WriteMemory(BaseAddressPtr, AlignedBase)
                : Instance._emulator.WriteMemory(BaseAddressPtr, (uint)AlignedBase);
            bool WroteSize = PointerSize == 8
                ? Instance._emulator.WriteMemory(NumberOfBytesToLockPtr, AlignedSize)
                : Instance._emulator.WriteMemory(NumberOfBytesToLockPtr, (uint)AlignedSize);

            return WroteBase && WroteSize ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }
    }
}
