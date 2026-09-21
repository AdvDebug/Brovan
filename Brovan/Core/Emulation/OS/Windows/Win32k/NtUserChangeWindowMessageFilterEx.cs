using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserChangeWindowMessageFilterEx : IWinSyscall
    {
        // One integrity level here, so no message is ever filtered.
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            Instance.SetLastWinError(Win32kHelper.ERROR_SUCCESS);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
