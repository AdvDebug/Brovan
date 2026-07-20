using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserGetExtendedPointerDeviceProperty : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            Instance.SetLastWinError(Win32kHelper.ERROR_CALL_NOT_IMPLEMENTED);
            Instance.SetRawSyscallReturn(0);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
