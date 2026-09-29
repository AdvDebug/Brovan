using Brovan.Core.Emulation.OS.SharedHelpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserRedrawWindow : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong RectPtr = Instance.WinHelper.GetArg(1);
            ulong Region = Instance.WinHelper.GetArg(2);
            uint Flags = (uint)Instance.WinHelper.GetArg32(3);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);

            // The re-run after the paint callback must not invalidate a second time.
            if (Win32kHelper.TakePaintRetry(Instance, Hwnd))
            {
                Instance.SetLastWinError(0);
                Instance.SetBooleanSyscallReturn(true);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Hwnd != 0 && Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            GdiClipRect Rect = default;
            if (RectPtr != 0 && !Win32kHelper.TryReadGuestRect(Instance, RectPtr, out Rect))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_NOACCESS);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if ((Flags & Win32kHelper.RDW_RESERVED) != 0)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_FLAGS);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            List<GdiClipRect> Area = Win32kHelper.GetRedrawArea(Instance);
            bool HasArea = Region != 0 && Win32kHelper.TryReadRegion(Instance, Region, Area);
            if (!HasArea && RectPtr != 0)
            {
                Area.Add(Rect);
                HasArea = true;
            }

            Win32kHelper.RedrawWindow(Instance, Window, HasArea ? Area : null, Flags);

            // WM_PAINT runs the window procedure, so this syscall runs again when the callback returns.
            if ((Flags & Win32kHelper.RDW_UPDATENOW) != 0 && Window != null && Window.Dirty && Win32kHelper.IsWindowShown(Instance, Window))
            {
                ulong SyscallRip = Instance.WinHelper.GetSyscallRip(Instance.CurrentThread, false);
                Window.Dirty = false;

                if (SyscallRip != 0 &&
                    Win32kHelper.InvokeWindowProc(Instance, Hwnd, Window.WndProc, Win32kHelper.WM_PAINT, 0, 0, null, SyscallRip, Hwnd))
                    return NTSTATUS.STATUS_SUCCESS;

                Win32kHelper.MarkWindowDirty(Instance, Window);
            }

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
