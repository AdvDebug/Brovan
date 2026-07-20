using System.Linq;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtTerminateJobObject : IWinSyscall
    {
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

            Job.IsTerminated = true;

            long ExitTime = Instance.GetEmulatedSystemTimeFileTimeUtc();
            uint ExitStatus = unchecked((uint)ExitCode);
            bool CurrentProcessInJob = false;

            foreach (uint ProcessId in Job.ProcessIds.Distinct())
            {
                WinProcess Process = Instance.WinHelper.WinProcesses.FirstOrDefault(P => P.PID == ProcessId);
                if (Process == null)
                    continue;

                Instance.WinHelper.UpdateProcessTimes(Process);
                if (Process.ExitTime == 0)
                    Process.ExitTime = ExitTime;

                if (Process.PID == Instance.WinHelper.PID)
                    CurrentProcessInJob = true;
            }

            if (CurrentProcessInJob)
            {
                if ((Instance.Settings.Flags & LogFlags.Important) != 0)
                    Instance.TriggerEventMessage($"[{(ExitStatus == 0 ? '+' : '!')}] Job asked to be terminated with exit code 0x{ExitStatus:X}", LogFlags.Important);

                foreach (EmulatedThread ProcessThread in Instance.Threads.Values)
                {
                    if (ProcessThread == null)
                        continue;

                    Instance.WinHelper.AbandonMutexesOwnedByThread(ProcessThread.ThreadId);
                    Instance.WinHelper.ClearTerminationState(ProcessThread);
                    ProcessThread.ExitCode = unchecked((int)ExitStatus);
                    ProcessThread.State = EmulatedThreadState.Terminated;
                }

                Instance.StopEmulation();
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
