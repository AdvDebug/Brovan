using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserMoveWindow : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hwnd = Instance.WinHelper.GetArg(0);
            int X = unchecked((int)Instance.WinHelper.GetArg(1));
            int Y = unchecked((int)Instance.WinHelper.GetArg(2));
            int Width = unchecked((int)Instance.WinHelper.GetArg(3));
            int Height = unchecked((int)Instance.WinHelper.GetArg(4));
            bool Repaint = Instance.WinHelper.GetArg(5) != 0;

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Window.X = X;
            Window.Y = Y;
            Window.Width = (uint)Math.Max(Width, 0);
            Window.Height = (uint)Math.Max(Height, 0);
            Window.Dirty = true;

            Instance.WinHelper.MaterializeUserWindow(Window);

            if (Repaint)
                Win32kHelper.InvalidateWindow(Instance, Hwnd);
            else
                Instance.WinHelper.PresentDesktop();

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
