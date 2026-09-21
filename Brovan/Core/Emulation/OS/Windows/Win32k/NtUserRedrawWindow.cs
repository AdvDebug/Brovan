using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserRedrawWindow : IWinSyscall
    {
        private const uint RdwInvalidate = 0x0001;
        private const uint RdwValidate = 0x0008;
        private const uint RdwUpdateNow = 0x0100;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            uint Flags = (uint)Instance.WinHelper.GetArg32(3);

            if ((Flags & RdwValidate) != 0)
            {
                WinWindow Target = Instance.WinHelper.GetWindow(Hwnd);
                if (Target == null)
                {
                    Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                    Instance.SetBooleanSyscallReturn(false);
                    return NTSTATUS.STATUS_SUCCESS;
                }

                Target.Dirty = false;
                Target.PaintPending = false;
                Instance.WinHelper.PublishWindowPaintState(Target);
                Instance.SetLastWinError(0);
                Instance.SetBooleanSyscallReturn(true);
                return NTSTATUS.STATUS_SUCCESS;
            }

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);

            // The re-run after the paint callback must not invalidate a second time.
            if (Win32kHelper.TakePaintRetry(Instance, Hwnd))
            {
                Instance.SetLastWinError(0);
                Instance.SetBooleanSyscallReturn(true);
                return NTSTATUS.STATUS_SUCCESS;
            }

            bool Success = (Flags & RdwInvalidate) != 0
                ? Win32kHelper.InvalidateWindow(Instance, Hwnd)
                : Hwnd == 0 || Window != null;

            // WM_PAINT runs the window procedure, so this syscall runs again when the callback returns.
            if (Success && (Flags & RdwUpdateNow) != 0 && Window != null && Window.Dirty && Window.Visible)
            {
                ulong SyscallRip = Instance.WinHelper.GetSyscallRip(Instance.CurrentThread, false);
                Window.Dirty = false;

                if (SyscallRip != 0 &&
                    Win32kHelper.InvokeWindowProc(Instance, Hwnd, Window.WndProc, Win32kHelper.WM_PAINT, 0, 0, null, SyscallRip, Hwnd))
                    return NTSTATUS.STATUS_SUCCESS;

                Win32kHelper.MarkWindowDirty(Instance, Window);
            }

            Instance.SetLastWinError(Success ? 0u : Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
            Instance.SetBooleanSyscallReturn(Success);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
