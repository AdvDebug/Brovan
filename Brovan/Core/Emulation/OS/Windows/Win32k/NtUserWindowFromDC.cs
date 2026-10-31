using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserWindowFromDC : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            Instance.SetRawSyscallReturn(Win32kHelper.GetHwndFromDc(Instance, Hdc));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
