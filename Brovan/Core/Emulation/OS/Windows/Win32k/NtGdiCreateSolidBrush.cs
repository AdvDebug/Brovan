using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiCreateSolidBrush : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            uint ColorRef = (uint)Instance.WinHelper.GetArg64(0);

            ulong BrushHandle = Win32kHelper.CreateSolidBrush(Instance, ColorRef);
            Instance.SetRawSyscallReturn(BrushHandle);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
