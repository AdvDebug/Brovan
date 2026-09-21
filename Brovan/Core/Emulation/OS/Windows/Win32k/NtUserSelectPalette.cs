using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserSelectPalette : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            ulong Palette = Instance.WinHelper.GetArg(1);

            Instance.SetLastWinError(0);
            Instance.SetRawSyscallReturn(Win32kHelper.SelectDcPalette(Instance, Hdc, Palette));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
