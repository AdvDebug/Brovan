using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiPatBlt : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong Hdc = Instance.WinHelper.GetArg(0);
            int X = unchecked((int)Instance.WinHelper.GetArg(1));
            int Y = unchecked((int)Instance.WinHelper.GetArg(2));
            int Width = unchecked((int)Instance.WinHelper.GetArg(3));
            int Height = unchecked((int)Instance.WinHelper.GetArg(4));
            uint Rop = (uint)Instance.WinHelper.GetArg(5);

            bool Drawn = Win32kHelper.PatBltDc(Instance, Hdc, X, Y, Width, Height, Rop, Instance.WinHelper.ReadDcSelectedBrush(Hdc));
            Instance.SetRawSyscallReturn(Drawn ? 1UL : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
