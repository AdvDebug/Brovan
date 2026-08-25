using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserShowCursor : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            bool Show = Instance.WinHelper.GetArg(0) != 0;

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(unchecked((ulong)(long)Win32kHelper.ShowCursor(Instance, Show)));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
