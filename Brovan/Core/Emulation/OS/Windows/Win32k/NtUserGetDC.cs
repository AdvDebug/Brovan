using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetDC : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong Hdc = Win32kHelper.CreateDeviceContext(Instance, Hwnd, false, false);

            if (Hdc == 0)
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            Instance.SetRawSyscallReturn(Hdc);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
