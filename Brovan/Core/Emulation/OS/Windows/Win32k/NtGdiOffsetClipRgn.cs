using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiOffsetClipRgn : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            int X = unchecked((int)Instance.WinHelper.GetArg(1));
            int Y = unchecked((int)Instance.WinHelper.GetArg(2));

            Instance.SetRawSyscallReturn((ulong)Win32kHelper.OffsetDcClip(Instance, Hdc, X, Y));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
