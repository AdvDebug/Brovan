using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetProcessDpiAwarenessContext : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            Instance.SetRawSyscallReturn(Win32kDpi.GetProcessContext(Instance));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
