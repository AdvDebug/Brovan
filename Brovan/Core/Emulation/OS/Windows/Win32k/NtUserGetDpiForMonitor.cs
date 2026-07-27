using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetDpiForMonitor : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Monitor = Instance.WinHelper.GetArg(0);
            uint DpiType = (uint)Instance.WinHelper.GetArg(1);
            ulong DpiXPtr = Instance.WinHelper.GetArg(2);
            ulong DpiYPtr = Instance.WinHelper.GetArg(3);

            if (Monitor == 0)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            uint Dpi = Win32kDpi.GetMonitorDpi(Instance, DpiType);

            if (DpiXPtr != 0 && Instance.IsRegionMapped(DpiXPtr, 4))
                Instance._emulator.WriteMemory(DpiXPtr, Dpi, 4);

            if (DpiYPtr != 0 && Instance.IsRegionMapped(DpiYPtr, 4))
                Instance._emulator.WriteMemory(DpiYPtr, Dpi, 4);

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
