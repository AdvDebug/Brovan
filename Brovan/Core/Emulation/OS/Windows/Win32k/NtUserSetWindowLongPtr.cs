using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetWindowLongPtr : IWinSyscall
    {
        private const uint ERROR_INVALID_INDEX = 1413;
        private const int GWLP_WNDPROC = -4;
        private const int GWLP_HINSTANCE = -6;
        private const int GWLP_ID = -12;
        private const int GWL_STYLE = -16;
        private const int GWL_EXSTYLE = -20;
        private const int GWLP_USERDATA = -21;
        private const uint WS_VISIBLE = 0x10000000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hwnd = Instance.WinHelper.GetArg(0);
            int Index = unchecked((int)(uint)Instance.WinHelper.GetArg(1));
            ulong NewValue = Instance.WinHelper.GetArg(2);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong Previous;
            switch (Index)
            {
                case GWL_STYLE:
                    Previous = Window.Style;
                    Window.Style = (uint)NewValue;
                    Window.Visible = (NewValue & WS_VISIBLE) != 0;
                    break;

                case GWL_EXSTYLE:
                    Previous = Window.ExStyle;
                    Window.ExStyle = (uint)NewValue;
                    break;

                case GWLP_USERDATA:
                    Previous = Window.UserData;
                    Window.UserData = NewValue;
                    break;

                case GWLP_WNDPROC:
                    Previous = Window.WndProc;
                    Window.WndProc = NewValue;
                    break;

                case GWLP_HINSTANCE:
                    Previous = Window.InstanceHandle;
                    Window.InstanceHandle = NewValue;
                    break;

                case GWLP_ID:
                    Previous = Window.MenuHandle;
                    Window.MenuHandle = NewValue;
                    break;

                default:
                    Instance.SetLastWinError(ERROR_INVALID_INDEX);
                    Instance.SetRawSyscallReturn(0);
                    return NTSTATUS.STATUS_SUCCESS;
            }

            Window.Dirty = true;
            Instance.WinHelper.MaterializeUserWindow(Window);
            Instance.WinHelper.PresentDesktop();

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Previous);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
