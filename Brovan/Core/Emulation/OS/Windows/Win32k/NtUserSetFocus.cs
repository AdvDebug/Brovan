using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetFocus : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hwnd = Instance.WinHelper.GetArg(0);
            if (Hwnd != 0 && Instance.WinHelper.GetWindow(Hwnd) == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong Previous = Instance.WinHelper.FocusWindow;
            Instance.WinHelper.FocusWindow = Hwnd;
            if (Hwnd != 0)
            {
                Instance.WinHelper.ActiveWindow = Hwnd;
                WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
                if (Window != null)
                    Instance.WinHelper.SetThreadWindowContext(Window);
            }

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Previous);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
