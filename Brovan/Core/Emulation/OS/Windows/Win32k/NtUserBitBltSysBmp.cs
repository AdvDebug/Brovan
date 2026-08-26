using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserBitBltSysBmp : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            int X = unchecked((int)Instance.WinHelper.GetArg(1));
            int Y = unchecked((int)Instance.WinHelper.GetArg(2));
            int Index = unchecked((int)Instance.WinHelper.GetArg(3));

            bool Drawn = Win32kHelper.DrawOemBitmap(Instance, Hdc, X, Y, Index);
            Instance.SetLastWinError(Drawn ? 0u : Win32kHelper.ERROR_INVALID_PARAMETER);
            Instance.SetBooleanSyscallReturn(Drawn);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
