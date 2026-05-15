using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetDpiForCurrentProcess : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            Instance.SetRawSyscallReturn(Win32kHelper.DEFAULT_SCREEN_DPI);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}