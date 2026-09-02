using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetPointerDevices : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong DeviceCountPtr = Instance.WinHelper.GetArg(0);

            if (DeviceCountPtr == 0 || !Instance.IsRegionMapped(DeviceCountPtr, 4))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance._emulator.WriteMemory(DeviceCountPtr, 0, 4);

            Instance.SetLastWinError(Win32kHelper.ERROR_SUCCESS);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
