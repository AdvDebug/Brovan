using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiExcludeClipRect : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            int Left = unchecked((int)Instance.WinHelper.GetArg(1));
            int Top = unchecked((int)Instance.WinHelper.GetArg(2));
            int Right = unchecked((int)Instance.WinHelper.GetArg(3));
            int Bottom = unchecked((int)Instance.WinHelper.GetArg(4));

            Instance.SetRawSyscallReturn((ulong)Win32kHelper.ClipDcRect(Instance, Hdc, Left, Top, Right, Bottom, true));
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
