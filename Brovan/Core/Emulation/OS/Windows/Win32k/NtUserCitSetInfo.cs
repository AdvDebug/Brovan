using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtUserCitSetInfo : IWinSyscall
    {
        // Input telemetry, which nothing here collects.
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            Instance.SetRawSyscallReturn(0);
            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
