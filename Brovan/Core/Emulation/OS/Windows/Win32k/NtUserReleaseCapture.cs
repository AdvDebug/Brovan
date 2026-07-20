using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserReleaseCapture : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            Win32kHelper.SetCaptureWindow(Instance, 0);
            Instance.SetLastWinError(0);
            Instance.SetBooleanSyscallReturn(true);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
