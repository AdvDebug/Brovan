using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserIsMouseInPointerEnabled : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            Instance.SetBooleanSyscallReturn(false);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
