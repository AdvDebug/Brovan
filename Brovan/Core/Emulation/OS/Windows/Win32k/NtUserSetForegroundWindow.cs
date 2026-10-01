using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetForegroundWindow : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hwnd = Instance.WinHelper.GetArg(0);
            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null || !Window.Visible)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            // NT: refused while another process holds the foreground.
            bool Refused = Win32kHelper.IsApplicationInBackground(Instance);
            Win32kHelper.ActivateWindow(Instance, Window, false);

            Instance.SetLastWinError(0);
            Win32kHelper.ReturnAfterNotifications(Instance, Refused ? 0UL : 1UL);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
