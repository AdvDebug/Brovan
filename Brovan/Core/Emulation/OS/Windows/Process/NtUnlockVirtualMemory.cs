using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal sealed class NtUnlockVirtualMemory : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
                return HandleCommon(Instance, Instance.WinHelper.GetArg64(0), Instance.WinHelper.GetArg64(1), Instance.WinHelper.GetArg64(2), 8);

            return HandleCommon(Instance, Instance.WinHelper.GetArg(0), Instance.WinHelper.GetArg(1), Instance.WinHelper.GetArg(2), 4);
        }

        private static NTSTATUS HandleCommon(BinaryEmulator Instance, ulong ProcessHandle, ulong BaseAddressPtr, ulong NumberOfBytesPtr, uint PointerSize)
        {
            if (!Instance.WinHelper.IsCurrentProcessHandle(ProcessHandle, AccessMask.ProcessVMOperation))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (BaseAddressPtr == 0 || NumberOfBytesPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(BaseAddressPtr, PointerSize) || !Instance.IsRegionMapped(NumberOfBytesPtr, PointerSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong BaseAddress = Instance.WinHelper.ReadPointer(BaseAddressPtr, PointerSize);
            ulong NumberOfBytes = Instance.WinHelper.ReadPointer(NumberOfBytesPtr, PointerSize);

            if (NumberOfBytes == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            const ulong PageSize = 0x1000;
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

            bool WroteBase = Instance._emulator.WriteMemory(BaseAddressPtr, AlignedBase, PointerSize);
            bool WroteSize = Instance._emulator.WriteMemory(NumberOfBytesPtr, AlignedSize, PointerSize);

            return WroteBase && WroteSize ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_ACCESS_VIOLATION;
        }
    }
}
