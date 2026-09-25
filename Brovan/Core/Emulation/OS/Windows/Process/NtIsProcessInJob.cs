using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtIsProcessInJob : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ProcessHandle = Instance.WinHelper.GetArg(0);
            ulong JobHandle = Instance.WinHelper.GetArg(1);

            return Instance.WinHelper.QueryProcessInJob(ProcessHandle, JobHandle);
        }
    }
}
