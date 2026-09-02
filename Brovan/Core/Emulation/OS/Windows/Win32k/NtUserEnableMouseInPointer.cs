using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserEnableMouseInPointer : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            Instance.SetLastWinError(Win32kHelper.ERROR_CALL_NOT_IMPLEMENTED);
            Instance.SetBooleanSyscallReturn(false);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
