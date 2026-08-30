namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetDisplayConfigBufferSizes : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong PathCountPtr = Instance.WinHelper.GetArg(1);
            ulong ModeCountPtr = Instance.WinHelper.GetArg(2);

            if (PathCountPtr == 0 || ModeCountPtr == 0)
                return Win32kDisplayConfig.Complete(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            if (!Instance.IsRegionMapped(PathCountPtr, 4) || !Instance.IsRegionMapped(ModeCountPtr, 4))
                return Win32kDisplayConfig.Complete(Instance, Win32kHelper.ERROR_INVALID_PARAMETER);

            Instance._emulator.WriteMemory(PathCountPtr, Win32kDisplayConfig.PathCount, 4);
            Instance._emulator.WriteMemory(ModeCountPtr, Win32kDisplayConfig.ModeCount, 4);
            return Win32kDisplayConfig.Complete(Instance, Win32kHelper.ERROR_SUCCESS);
        }
    }
}
