using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtDCompositionEnableMMCSS : IWinSyscall
    {
        // No host counterpart for multimedia class scheduling.
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            Instance.SetRawSyscallReturn(0);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
