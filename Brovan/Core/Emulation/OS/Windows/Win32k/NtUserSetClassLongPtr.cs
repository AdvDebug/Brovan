using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetClassLongPtr : IWinSyscall
    {
        private const int GclpHbrBackground = -10;
        private const int GclpHcursor = -12;
        private const int GclpHicon = -14;
        private const int GclpHmodule = -16;
        private const int GclCbWndExtra = -18;
        private const int GclCbClsExtra = -20;
        private const int GclpWndProc = -24;
        private const int GclStyle = -26;
        private const int GclpHiconSm = -34;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            int Index = unchecked((int)Instance.WinHelper.GetArg32(1));
            ulong Value = Instance.WinHelper.GetArg(2);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            WinWindowClass Class = Window == null || Window.ClassAtom == 0
                ? null
                : Instance.WinHelper.GetWindowClass(Window.ClassAtom);

            if (Class == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong Previous;
            switch (Index)
            {
                case GclpHbrBackground:
                    Previous = Class.BackgroundBrush;
                    Class.BackgroundBrush = Value;
                    break;
                case GclpHcursor:
                    Previous = Class.CursorHandle;
                    Class.CursorHandle = Value;
                    break;
                case GclpHicon:
                    Previous = Class.IconHandle;
                    Class.IconHandle = Value;
                    break;
                case GclpHiconSm:
                    Previous = Class.SmallIconHandle;
                    Class.SmallIconHandle = Value;
                    break;
                case GclpHmodule:
                    Previous = Class.InstanceHandle;
                    Class.InstanceHandle = Value;
                    break;
                case GclpWndProc:
                    Previous = Class.WndProc;
                    Class.WndProc = Value;
                    break;
                case GclStyle:
                    Previous = Class.Style;
                    Class.Style = (uint)Value;
                    break;
                case GclCbClsExtra:
                    Previous = (ulong)Class.ClassExtraBytes;
                    Class.ClassExtraBytes = unchecked((int)Value);
                    break;
                case GclCbWndExtra:
                    Previous = (ulong)Class.WindowExtraBytes;
                    Class.WindowExtraBytes = unchecked((int)Value);
                    break;
                default:
                    Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                    Instance.SetRawSyscallReturn(0);
                    return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetLastWinError(Win32kHelper.ERROR_SUCCESS);
            Instance.SetRawSyscallReturn(Previous);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
