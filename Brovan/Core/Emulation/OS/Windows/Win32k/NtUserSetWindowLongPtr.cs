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

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hwnd = Instance.WinHelper.GetArg(0);
            int Index = unchecked((int)(uint)Instance.WinHelper.GetArg(1));
            ulong NewValue = Instance.WinHelper.GetArg(2);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
                return Win32kHelper.FailWithError(Instance, Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);

            ulong Previous;
            switch (Index)
            {
                case GWL_STYLE:
                    Previous = Window.Style;
                    Window.Style = (uint)NewValue;
                    Window.Visible = (NewValue & Win32kHelper.WindowStyleVisible) != 0;
                    break;

                case GWL_EXSTYLE:
                    Previous = Window.ExStyle;
                    // The visible state bit shares this dword client-side and belongs to Visible.
                    Win32kHelper.SetExStyle(Window, (uint)NewValue & ~WinSysHelper.UserWindowStateVisible);
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
                    if (!Win32kHelper.TryExchangeWindowExtra(Instance, Window, Index, NewValue, 8, out Previous))
                        return Win32kHelper.FailWithError(Instance, ERROR_INVALID_INDEX);

                    Instance.SetLastWinError(0);
                    Instance.SetRawSyscallReturn(Previous);
                    return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.WinHelper.MaterializeUserWindow(Window);
            Instance.WinHelper.PresentDesktop();

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Previous);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
