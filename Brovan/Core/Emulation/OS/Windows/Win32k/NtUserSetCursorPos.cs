using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetCursorPos : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            int X = unchecked((int)Instance.WinHelper.GetArg(0));
            int Y = unchecked((int)Instance.WinHelper.GetArg(1));

            Win32kHelper.SetCursorPosition(Instance, X, Y);

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
