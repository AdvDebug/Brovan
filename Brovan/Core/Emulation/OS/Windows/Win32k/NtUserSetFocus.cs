using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetFocus : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hwnd = Instance.WinHelper.GetArg(0);
            WinWindow Window = Hwnd == 0 ? null : Instance.WinHelper.GetWindow(Hwnd);
            if (Hwnd != 0 && Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong Previous = Instance.WinHelper.FocusWindow;

            // NT: focus in another top-level window activates that window.
            if (Window != null)
            {
                WinWindow Root = Instance.WinHelper.GetRootWindow(Window);
                if (Root != null && Root.Hwnd != Instance.WinHelper.ActiveWindow)
                    Win32kHelper.ActivateWindow(Instance, Root, false);

                Instance.WinHelper.SetThreadWindowContext(Window);
            }

            Win32kHelper.MoveFocus(Instance, Hwnd, false);

            Instance.SetLastWinError(0);
            Win32kHelper.ReturnAfterNotifications(Instance, Previous);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
