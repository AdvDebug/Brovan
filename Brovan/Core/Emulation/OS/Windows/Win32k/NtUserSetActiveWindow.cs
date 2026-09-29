using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetActiveWindow : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            const uint WS_CHILD = 0x40000000;
            const uint WS_POPUP = 0x80000000;

            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong Previous = Instance.WinHelper.ActiveWindow;

            if (Hwnd == 0)
            {
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            // NT: a child window is refused, and the old active window is still returned.
            if ((Window.Style & (WS_CHILD | WS_POPUP)) != WS_CHILD)
                Win32kHelper.ActivateWindow(Instance, Window, false);

            Instance.SetRawSyscallReturn(Previous);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
