using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserUpdateWindow : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetLastWinError(0);

            // WM_PAINT answers to the window procedure, so this syscall runs again once the callback returns.
            if (Window.Dirty && Window.Visible)
            {
                ulong SyscallRip = Instance.WinHelper.GetSyscallRip(Instance.CurrentThread, false);
                Window.Dirty = false;

                if (SyscallRip != 0 &&
                    Win32kHelper.InvokeWindowProc(Instance, Hwnd, Window.WndProc, Win32kHelper.WM_PAINT, 0, 0, null, SyscallRip))
                    return NTSTATUS.STATUS_SUCCESS;

                Window.Dirty = true;
            }

            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
