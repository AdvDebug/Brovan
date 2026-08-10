using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetDoubleClickTime : IWinSyscall
    {
        private const uint DefaultDoubleClickTime = 500;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            Instance.SetRawSyscallReturn(DefaultDoubleClickTime);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
