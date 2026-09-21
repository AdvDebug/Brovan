using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserWindowFromPoint : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            int X = unchecked((int)Instance.WinHelper.GetArg(0));
            int Y = unchecked((int)Instance.WinHelper.GetArg(1));

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Win32kHelper.WindowFromPoint(Instance, X, Y));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
