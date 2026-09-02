using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetDisplayConfigBufferSizes : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong PathCountPtr = Instance.WinHelper.GetArg(1);

            if (PathCountPtr == 0 || !Instance.IsRegionMapped(PathCountPtr, 4))
                return Win32kDisplayConfig.Complete(Instance, NTSTATUS.STATUS_INVALID_PARAMETER);

            Instance._emulator.WriteMemory(PathCountPtr, Win32kDisplayConfig.PathCount, 4);
            return Win32kDisplayConfig.Complete(Instance, NTSTATUS.STATUS_SUCCESS);
        }
    }
}
