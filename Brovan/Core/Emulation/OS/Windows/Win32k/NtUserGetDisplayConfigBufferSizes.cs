using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetDisplayConfigBufferSizes : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong PathCountPtr = Instance.WinHelper.GetArg(1);
            ulong ModeCountPtr = Instance.WinHelper.GetArg(2);

            if (PathCountPtr == 0 || !Instance.IsRegionMapped(PathCountPtr, 4))
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            Instance._emulator.WriteMemory(PathCountPtr, 1u, 4);

            if (ModeCountPtr != 0 && Instance.IsRegionMapped(ModeCountPtr, 4))
                Instance._emulator.WriteMemory(ModeCountPtr, 2u, 4);

            Instance.SetRawSyscallReturn(0);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
