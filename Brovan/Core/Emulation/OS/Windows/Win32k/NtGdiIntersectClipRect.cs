using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiIntersectClipRect : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            Instance.WinHelper.GetArg(0);
            int Left = unchecked((int)Instance.WinHelper.GetArg(1));
            int Top = unchecked((int)Instance.WinHelper.GetArg(2));
            int Right = unchecked((int)Instance.WinHelper.GetArg(3));
            int Bottom = unchecked((int)Instance.WinHelper.GetArg(4));

            ulong Result = (Left < Right && Top < Bottom) ? 1ul : 3ul;
            Instance.SetRawSyscallReturn(Result);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
