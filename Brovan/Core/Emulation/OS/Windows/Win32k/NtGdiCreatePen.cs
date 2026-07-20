using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiCreatePen : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            int Style = unchecked((int)Instance.WinHelper.GetArg(0));
            int Width = unchecked((int)Instance.WinHelper.GetArg(1));
            uint ColorRef = (uint)Instance.WinHelper.GetArg(2);

            ulong PenHandle = Win32kHelper.CreatePen(Instance, Style, Width, ColorRef);
            Instance.SetRawSyscallReturn(PenHandle);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
