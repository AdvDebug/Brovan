using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiCreateCompatibleDC : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Win32kHelper.CreateDeviceContext(Instance, 0, false, false);
            Instance.SetLastWinError(Hdc == 0 ? Win32kHelper.ERROR_INVALID_PARAMETER : 0u);
            Instance.SetRawSyscallReturn(Hdc);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
