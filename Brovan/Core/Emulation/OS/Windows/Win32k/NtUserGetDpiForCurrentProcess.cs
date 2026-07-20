using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetDpiForCurrentProcess : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            Instance.SetRawSyscallReturn(Win32kHelper.DEFAULT_SCREEN_DPI);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}