using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiCreateSolidBrush : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            uint ColorRef = (uint)Instance.WinHelper.GetArg(0);

            ulong BrushHandle = Win32kHelper.CreateSolidBrush(Instance, ColorRef);
            Instance.SetRawSyscallReturn(BrushHandle);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
