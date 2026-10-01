using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiPtVisible : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            int X = unchecked((int)Instance.WinHelper.GetArg(1));
            int Y = unchecked((int)Instance.WinHelper.GetArg(2));

            Instance.SetRawSyscallReturn(Win32kHelper.IsDcAreaVisible(Instance, Hdc, X, Y, X + 1, Y + 1) ? 1UL : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
