using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiSelectFont : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            ulong Font = Instance.WinHelper.GetArg(1);

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Win32kHelper.SelectFont(Instance, Hdc, Font));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
