using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserShowWindow : IWinSyscall
    {
        private const uint SW_HIDE = 0;
        private const uint SW_SHOWNORMAL = 1;
        private const uint SW_SHOWMINIMIZED = 2;
        private const uint SW_SHOWMAXIMIZED = 3;
        private const uint SW_SHOWNOACTIVATE = 4;
        private const uint SW_SHOW = 5;
        private const uint SW_MINIMIZE = 6;
        private const uint SW_SHOWMINNOACTIVE = 7;
        private const uint SW_SHOWNA = 8;
        private const uint SW_RESTORE = 9;
        private const uint SW_SHOWDEFAULT = 10;
        private const uint SW_FORCEMINIMIZE = 11;
        private const uint WS_VISIBLE = 0x10000000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            uint Command = (uint)Instance.WinHelper.GetArg(1);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Command > SW_FORCEMINIMIZE)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            bool WasVisible = Window.Visible;
            bool WasMinimized = Window.Minimized;
            bool Normal = !Window.Minimized && !Window.Maximized;

            // NT: xxxShowWindowEx ignores a command that changes nothing.
            if ((Command == SW_HIDE && !WasVisible)
                || (WasVisible && (Command == SW_SHOW || Command == SW_SHOWNA))
                || (WasVisible && Normal && (Command == SW_SHOWNORMAL || Command == SW_SHOWNOACTIVATE
                    || Command == SW_RESTORE || Command == SW_SHOWDEFAULT)))
            {
                Instance.SetRawSyscallReturn(WasVisible ? 1ul : 0ul);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Window.Visible = Command != SW_HIDE;
            bool Activate = false;
            bool Minimizing = false;

            switch (Command)
            {
                case SW_SHOWMINIMIZED:
                case SW_MINIMIZE:
                case SW_SHOWMINNOACTIVE:
                case SW_FORCEMINIMIZE:
                    Win32kHelper.SetShowState(Window, true, Window.Maximized);
                    Activate = Command == SW_SHOWMINIMIZED;
                    Minimizing = Command == SW_MINIMIZE || Command == SW_FORCEMINIMIZE;
                    break;

                case SW_SHOWMAXIMIZED:
                    Win32kHelper.SetShowState(Window, false, true);
                    Activate = true;
                    break;

                case SW_RESTORE:
                    Win32kHelper.SetShowState(Window, false, Window.Minimized && Window.Maximized);
                    Activate = true;
                    break;

                case SW_SHOWNOACTIVATE:
                    Win32kHelper.SetShowState(Window, false, false);
                    break;

                case SW_SHOW:
                    Activate = true;
                    break;

                case SW_HIDE:
                case SW_SHOWNA:
                    break;

                default:
                    Win32kHelper.SetShowState(Window, false, false);
                    Activate = true;
                    break;
            }

            Window.Style = Window.Visible ? Window.Style | WS_VISIBLE : Window.Style & ~WS_VISIBLE;
            Window.RedrawDisabled = false;

            if (Window.ParentHwnd == 0)
                Instance.WinHelper.LinkTopLevelWindow(Window);

            if (Window.Visible)
            {
                Instance.WinHelper.SetThreadWindowContext(Window);

                if (!WasVisible || (WasMinimized && !Window.Minimized))
                    Win32kHelper.InvalidateWholeWindow(Instance, Window);
                else if (Window.Minimized)
                    Win32kHelper.ClearChildUpdateTrees(Instance, Window);
                else
                    Win32kHelper.MarkWindowDirty(Instance, Window);

                if (!WasVisible)
                    Win32kHelper.InvalidateParentArea(Instance, Window);
            }
            else
            {
                Win32kHelper.ClearUpdateTree(Instance, Window);
                Win32kHelper.InvalidateParentArea(Instance, Window);
            }

            // user32 answers IsWindowVisible and GetWindowLong out of the client window object.
            Instance.WinHelper.MaterializeUserWindow(Window);

            if (Window.ParentHwnd == 0)
            {
                bool Leaving = (!Window.Visible || Minimizing) && Window.Hwnd == Instance.WinHelper.ActiveWindow;
                if (Leaving)
                    Win32kHelper.ActivateNextWindow(Instance, Window);
                else if (Activate && Win32kHelper.CanActivateImplicitly(Window))
                    Win32kHelper.ActivateWindow(Instance, Window, false);
            }

            Instance.WinHelper.PresentDesktop();

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(WasVisible ? 1ul : 0ul);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
