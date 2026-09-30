using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetActiveWindow : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong Previous = Instance.WinHelper.ActiveWindow;

            if (Hwnd == 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            // NT: another thread's window is refused with no error.
            if (!Win32kHelper.OwnedByThread(Window, Instance.CurrentThread?.ThreadId ?? 0))
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            // NT: a child window is refused, and the old active window is still returned.
            if ((Window.Style & (Win32kHelper.WindowStyleChild | Win32kHelper.WindowStylePopup)) != Win32kHelper.WindowStyleChild)
                Win32kHelper.ActivateWindow(Instance, Window, false);

            Win32kHelper.ReturnAfterNotifications(Instance, Previous);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
