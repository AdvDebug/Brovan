using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetRequiredCursorSizes : IWinSyscall
    {
        // One cursor size is served here, so user32 has no per-DPI variants to build.
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            Instance.SetLastWinError(Win32kHelper.ERROR_SUCCESS);
            Instance.SetBooleanSyscallReturn(false);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
