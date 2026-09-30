using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserEnableWindow : IWinSyscall
    {
        private const uint WM_ENABLE = 0x000A;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            bool Enable = Instance.WinHelper.GetArg(1) != 0;

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            bool WasDisabled = (Window.Style & Win32kHelper.WindowStyleDisabled) != 0;
            if (WasDisabled == Enable)
            {
                Window.Style = Enable ? Window.Style & ~Win32kHelper.WindowStyleDisabled : Window.Style | Win32kHelper.WindowStyleDisabled;
                Instance.WinHelper.MaterializeUserWindow(Window);

                // A disabled host window passes clicks to the window it owns.
                if (Window.ParentHwnd == 0)
                    Instance.WinHelper.PresentDesktop();

                Instance.SetLastWinError(0);

                // NT: xxxEnableWindow sends WM_ENABLE before it returns.
                if (Win32kHelper.IsOwnedByCurrentThread(Instance, Window)
                    && Instance.WinHelper.BeginGuestCall(Window.WndProc, Hwnd, WM_ENABLE, Enable ? 1UL : 0UL, 0, WasDisabled ? 1UL : 0UL))
                {
                    return NTSTATUS.STATUS_SUCCESS;
                }

                Win32kHelper.PostMessage(Instance, Hwnd, WM_ENABLE, Enable ? 1UL : 0UL, 0);
            }

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(WasDisabled);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
