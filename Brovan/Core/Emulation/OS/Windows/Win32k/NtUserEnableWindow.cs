using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserEnableWindow : IWinSyscall
    {
        private const uint WS_DISABLED = 0x08000000;
        private const uint WM_ENABLE = 0x000A;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            bool Enable = Instance.WinHelper.GetArg(1) != 0;

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            bool WasDisabled = (Window.Style & WS_DISABLED) != 0;
            if (WasDisabled == Enable)
            {
                Window.Style = Enable ? Window.Style & ~WS_DISABLED : Window.Style | WS_DISABLED;
                Instance.WinHelper.MaterializeUserWindow(Window);
                Win32kHelper.PostMessage(Instance, Hwnd, WM_ENABLE, Enable ? 1UL : 0UL, 0);
            }

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(WasDisabled);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
