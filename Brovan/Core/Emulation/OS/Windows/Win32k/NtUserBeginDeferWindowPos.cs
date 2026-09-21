using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserBeginDeferWindowPos : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Win32kHelper.BeginDeferWindowPos(Instance));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
