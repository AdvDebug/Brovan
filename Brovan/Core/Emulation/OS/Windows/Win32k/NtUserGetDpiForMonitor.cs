using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetDpiForMonitor : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong DpiXPtr = Instance.WinHelper.GetArg(2);
            ulong DpiYPtr = Instance.WinHelper.GetArg(3);

            if (DpiXPtr != 0 && Instance.IsRegionMapped(DpiXPtr, 4))
                Instance._emulator.WriteMemory(DpiXPtr, Win32kHelper.DEFAULT_SCREEN_DPI, 4);

            if (DpiYPtr != 0 && Instance.IsRegionMapped(DpiYPtr, 4))
                Instance._emulator.WriteMemory(DpiYPtr, Win32kHelper.DEFAULT_SCREEN_DPI, 4);

            Instance.SetRawSyscallReturn(0);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
