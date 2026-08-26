using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetParent : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);
            ulong NewParentHwnd = Instance.WinHelper.GetArg(1);

            WinWindow Window = Instance.WinHelper.GetWindow(Hwnd);
            if (Window == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            WinWindow NewParent = NewParentHwnd == 0 ? null : Instance.WinHelper.GetWindow(NewParentHwnd);
            if (NewParentHwnd != 0 && NewParent == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            ulong Previous = Window.ParentHwnd;
            if (!Instance.WinHelper.ReparentWindow(Window, NewParent))
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_PARAMETER);
                Instance.SetRawSyscallReturn(0);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Previous);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
