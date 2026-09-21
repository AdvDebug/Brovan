using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiRestoreDC : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong Hdc = Instance.WinHelper.GetArg(0);
            int Level = unchecked((int)Instance.WinHelper.GetArg(1));

            bool Restored = Win32kHelper.RestoreDeviceContext(Instance, Hdc, Level);

            Instance.SetLastWinError(Restored ? Win32kHelper.ERROR_SUCCESS : Win32kHelper.ERROR_INVALID_PARAMETER);
            Instance.SetRawSyscallReturn(Restored ? 1UL : 0UL);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
