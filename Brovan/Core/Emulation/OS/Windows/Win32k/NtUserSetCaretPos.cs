using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetCaretPos : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            int X = unchecked((int)Instance.WinHelper.GetArg(0));
            int Y = unchecked((int)Instance.WinHelper.GetArg(1));

            Win32kHelper.Win32kCaret Caret = Win32kHelper.GetOwnedCaret(Instance, 0);
            if (Caret == null)
            {
                Instance.SetLastWinError(Win32kHelper.ERROR_ACCESS_DENIED);
                Instance.SetBooleanSyscallReturn(false);
                return NTSTATUS.STATUS_SUCCESS;
            }

            Caret.X = X;
            Caret.Y = Y;
            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
