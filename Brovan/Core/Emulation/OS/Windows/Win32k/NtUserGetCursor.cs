using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetCursor : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            Instance.SetLastWinError(Win32kHelper.ERROR_SUCCESS);
            Instance.SetRawSyscallReturn(Win32kHelper.GetCursorHandle(Instance));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
