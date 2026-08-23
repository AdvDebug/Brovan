using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtWow64GetCurrentProcessorNumber : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            Instance.SetRawSyscallReturn(0);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
