using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserHideCaret : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hwnd = Instance.WinHelper.GetArg(0);

            if (Hwnd != 0 && Instance.WinHelper.GetWindow(Hwnd) == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_INVALID_WINDOW_HANDLE);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Win32kHelper.Win32kCaret Caret = Win32kHelper.GetOwnedCaret(Instance, Hwnd);
            if (Caret == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_ACCESS_DENIED);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Caret.ShowCount--;
            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
