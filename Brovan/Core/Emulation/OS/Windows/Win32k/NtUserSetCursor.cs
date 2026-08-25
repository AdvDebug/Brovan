using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSetCursor : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Cursor = Instance.WinHelper.GetArg(0);

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Win32kHelper.SetCursorHandle(Instance, Cursor));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
