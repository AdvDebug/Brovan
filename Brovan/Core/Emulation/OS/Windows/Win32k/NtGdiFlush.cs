using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiFlush : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            Instance.WinHelper.FlushGdiBatch();
            Instance.SetRawSyscallReturn(1);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
