using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserShowWindow : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            const uint ERROR_INVALID_WINDOW_HANDLE = 1400;
            const int SW_HIDE = 0;
            const int SW_SHOWMINIMIZED = 2;
            const int SW_SHOWMAXIMIZED = 3;
            const int SW_SHOWMINNOACTIVE = 7;
            const int SW_RESTORE = 9;
            const int SW_FORCEMINIMIZE = 11;
            const uint WS_VISIBLE = 0x10000000;

            ulong Hwnd = Instance.WinHelper.GetArg64(0);
            int Command = unchecked((int)Instance.WinHelper.GetArg64(1, true));

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            bool WasVisible = Window.Visible;

            switch (Command)
            {
                case SW_HIDE:
                    Window.Visible = false;
                    Window.Minimized = false;
                    Window.Maximized = false;
                    Window.Style &= ~WS_VISIBLE;
                    break;

                case SW_SHOWMINIMIZED:
                case SW_SHOWMINNOACTIVE:
                case SW_FORCEMINIMIZE:
                    Window.Visible = true;
                    Window.Minimized = true;
                    Window.Maximized = false;
                    Window.Style |= WS_VISIBLE;
                    break;

                case SW_SHOWMAXIMIZED:
                    Window.Visible = true;
                    Window.Minimized = false;
                    Window.Maximized = true;
                    Window.Style |= WS_VISIBLE;
                    break;

                case SW_RESTORE:
                default:
                    Window.Visible = true;
                    Window.Minimized = false;
                    Window.Maximized = false;
                    Window.Style |= WS_VISIBLE;
                    break;
            }

            Window.Dirty = true;

            if (Window.ParentHwnd == 0 && Window.Visible && !Instance.WinHelper.TopLevelWindows.Contains(Window.Hwnd))
                Instance.WinHelper.TopLevelWindows.Add(Window.Hwnd);

            if (Window.Visible)
            {
                if (Instance.WinHelper.ActiveWindow == 0)
                    Instance.WinHelper.ActiveWindow = Window.Hwnd;

                if (Instance.WinHelper.FocusWindow == 0)
                    Instance.WinHelper.FocusWindow = Window.Hwnd;
            }

            Instance.WinHelper.PresentDesktop();

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(WasVisible ? 1ul : 0ul);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}