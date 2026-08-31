using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserHideCursorNoCapture : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            Win32kHelper.HideCursorWhileTyping(Instance);

            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
