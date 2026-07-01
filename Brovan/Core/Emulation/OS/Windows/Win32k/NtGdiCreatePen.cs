using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiCreatePen : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            int Style = unchecked((int)Instance.WinHelper.GetArg64(0, true));
            int Width = unchecked((int)Instance.WinHelper.GetArg64(1, true));
            uint ColorRef = (uint)Instance.WinHelper.GetArg64(2);

            ulong PenHandle = Win32kHelper.CreatePen(Instance, Style, Width, ColorRef);
            Instance.SetRawSyscallReturn(PenHandle);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
