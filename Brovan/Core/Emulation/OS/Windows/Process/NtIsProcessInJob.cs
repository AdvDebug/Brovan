using System.Reflection.Metadata;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtIsProcessInJob : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong ProcessHandle = Instance.WinHelper.GetArg(0);
                ulong JobHandle = Instance.WinHelper.GetArg(1);
                if (!Instance.WinHelper.HandleExists(JobHandle))
                    return NTSTATUS.STATUS_INVALID_HANDLE;
                bool IsInJob = Instance.WinHelper.IsProcessInJob(ProcessHandle, JobHandle);
                return IsInJob ? NTSTATUS.STATUS_PROCESS_IN_JOB : NTSTATUS.STATUS_SUCCESS;
            }

            uint ProcessHandle32 = (uint)Instance.WinHelper.GetArg(0);
            uint JobHandle32 = (uint)Instance.WinHelper.GetArg(1);
            bool IsInJob32 = Instance.WinHelper.IsProcessInJob(ProcessHandle32, JobHandle32);
            if (!Instance.WinHelper.HandleExists(JobHandle32))
                return NTSTATUS.STATUS_INVALID_HANDLE;
            return IsInJob32 ? NTSTATUS.STATUS_PROCESS_IN_JOB : NTSTATUS.STATUS_SUCCESS;
        }
    }
}
