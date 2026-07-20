using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQuerySystemTime : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong SystemTimePtr = Instance.WinHelper.GetArg(0);
            if (SystemTimePtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(SystemTimePtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            long Now = Instance.GetEmulatedSystemTimeFileTimeUtc();
            if (!Instance._emulator.WriteMemory(SystemTimePtr, unchecked((ulong)Now), 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
