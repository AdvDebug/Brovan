using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserEnableNonClientDpiScaling : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);

            if (Hwnd == 0 || Instance.WinHelper.GetWindow(Hwnd) == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
