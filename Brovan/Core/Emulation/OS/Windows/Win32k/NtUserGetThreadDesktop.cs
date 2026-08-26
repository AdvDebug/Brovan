using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    // Brovan runs one desktop, so the thread the caller names does not change the answer.
    internal class NtUserGetThreadDesktop : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Instance.WinHelper.EnsureThreadDesktopHandle());
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
