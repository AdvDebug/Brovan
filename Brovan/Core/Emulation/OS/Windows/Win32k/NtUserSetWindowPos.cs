using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetWindowPos : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            const uint ERROR_INVALID_WINDOW_HANDLE = 1400;
            const uint SWP_NOSIZE = 0x0001;
            const uint SWP_NOMOVE = 0x0002;
            const uint SWP_NOZORDER = 0x0004;
            const uint SWP_SHOWWINDOW = 0x0040;
            const uint SWP_HIDEWINDOW = 0x0080;
            const uint WS_VISIBLE = 0x10000000;

            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong InsertAfter = Instance.WinHelper.GetArg(1);
            int X = unchecked((int)Instance.WinHelper.GetArg(2));
            int Y = unchecked((int)Instance.WinHelper.GetArg(3));
            int cx = unchecked((int)Instance.WinHelper.GetArg(4));
            int cy = unchecked((int)Instance.WinHelper.GetArg(5));
            uint Flags = (uint)Instance.WinHelper.GetArg(6);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if ((Flags & SWP_NOMOVE) == 0)
            {
                Window.X = X;
                Window.Y = Y;
            }

            if ((Flags & SWP_NOSIZE) == 0)
            {
                Window.Width = (uint)Math.Max(cx, 0);
                Window.Height = (uint)Math.Max(cy, 0);
            }

            if ((Flags & SWP_HIDEWINDOW) != 0)
            {
                Window.Visible = false;
                Window.Style &= ~WS_VISIBLE;
            }
            else if ((Flags & SWP_SHOWWINDOW) != 0)
            {
                Window.Visible = true;
                Window.Style |= WS_VISIBLE;
            }

            if ((Flags & SWP_NOZORDER) == 0)
            {
                Instance.WinHelper.UpdateTopLevelWindowZOrder(Hwnd, InsertAfter);
            }

            Window.Dirty = true;
            Instance.WinHelper.PresentDesktop();

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}