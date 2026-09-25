using System.Linq;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtTerminateJobObject : IWinSyscall
    {
        internal const uint JobLimitKillOnJobClose = 0x2000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong JobHandle = Instance.WinHelper.GetArg(0);
                ulong ExitCode = (uint)Instance.WinHelper.GetArg(1);
                return TerminateJob(Instance, JobHandle, ExitCode);
            }

            uint JobHandle32 = (uint)Instance.WinHelper.GetArg(0);
            uint ExitCode32 = (uint)Instance.WinHelper.GetArg(1);
            return TerminateJob(Instance, JobHandle32, ExitCode32);
        }

        private static NTSTATUS TerminateJob(BinaryEmulator Instance, ulong JobHandle, ulong ExitCode)
        {
            if (JobHandle == 0 || !Instance.WinHelper.HandleManager.HandleExists(JobHandle, HandleType.JobHandle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            WinJob Job = Instance.WinHelper.GetJobByHandle(JobHandle, AccessMask.GiveTemp);
            if (Job == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            TerminateMembers(Instance, Job, unchecked((uint)ExitCode), true);
            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static void TerminateMembers(BinaryEmulator Instance, WinJob Job, uint ExitStatus, bool EndSelf)
        {
            Job.IsTerminated = true;

            long ExitTime = Instance.GetEmulatedSystemTimeFileTimeUtc();
            bool CurrentProcessInJob = false;

            foreach (uint ProcessId in Job.ProcessIds)
            {
                WinProcess Process = Instance.WinHelper.WinProcesses.FirstOrDefault(P => P.PID == ProcessId);
                if (Process == null)
                    continue;

                if (Process.PID == Instance.WinHelper.PID)
                {
                    CurrentProcessInJob = true;
                    continue;
                }

                if (!WinSysHelper.IsProcessAlive(Process))
                    continue;

                if (Process.Remote != null)
                {
                    Process.Remote.Terminate(ExitStatus);
                    continue;
                }

                Instance.WinHelper.UpdateProcessTimes(Process);
                if (!Process.Threadless)
                    Process.ExitStatus = ExitStatus;
                Process.ExitTime = ExitTime;
            }

            Instance.WakeSignal.Bump();

            if (CurrentProcessInJob && EndSelf)
                NtTerminateProcess.TerminateCurrentProcess(Instance, ExitStatus);
        }

        internal static void CloseJobsOfExitingProcess(BinaryEmulator Instance)
        {
            foreach (KeyValuePair<ulong, IHandleObject> Handle in Instance.WinHelper.HandleManager.SnapshotHandles())
            {
                if (Handle.Value is WinJob Job && (Job.LimitFlags & JobLimitKillOnJobClose) != 0)
                    TerminateMembers(Instance, Job, 0, false);
            }
        }
    }
}
