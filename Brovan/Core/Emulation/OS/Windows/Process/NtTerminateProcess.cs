using Brovan.Core.Helpers;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtTerminateProcess : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ProcessHandle = Instance.WinHelper.GetArg(0);
            uint ExitCode = (uint)Instance.WinHelper.GetArg(1);

            // NT: NULL ends every thread but the caller.
            if (ProcessHandle == 0)
            {
                TerminateThreads(Instance, ExitCode, true);
                return NTSTATUS.STATUS_SUCCESS;
            }

            NTSTATUS Status = Instance.WinHelper.ResolveProcessHandle(ProcessHandle, AccessMask.ProcessTerminate, out WinProcess Process);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            if (Process.PID == Instance.WinHelper.PID)
            {
                TerminateCurrentProcess(Instance, ExitCode);
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (Process.Remote != null)
                return Process.Remote.Terminate(ExitCode);

            // A listed process runs nothing, so ending it only marks it exited.
            if (Process.ExitTime == 0)
            {
                Instance.WinHelper.UpdateProcessTimes(Process);
                if (!Process.Threadless)
                    Process.ExitStatus = ExitCode;
                Process.ExitTime = Instance.GetEmulatedSystemTimeFileTimeUtc();
                Instance.WakeSignal.Bump();
            }

            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static void TerminateCurrentProcess(BinaryEmulator Instance, uint ExitCode)
        {
            if ((Instance.Settings.Flags & LogFlags.Important) != 0)
                Instance.TriggerEventMessage($"[{(ExitCode == 0 ? '+' : '!')}] Process asked to be terminated with exit code 0x{ExitCode:X}", LogFlags.Important);

            NtTerminateJobObject.CloseJobsOfExitingProcess(Instance);
            GuestSession.PublishExit(ExitCode);
            Environment.ExitCode = (int)ExitCode;
            TerminateThreads(Instance, ExitCode, false);
            Instance.WinHelper.HideDesktopWindow();
            Instance.StopEmulation();
        }

        private static void TerminateThreads(BinaryEmulator Instance, uint ExitCode, bool SpareCaller)
        {
            uint Caller = (uint)Instance.CurrentThreadId;
            List<EmulatedThread> Threads = new List<EmulatedThread>(Instance.Threads.Values);

            foreach (EmulatedThread Thread in Threads)
            {
                if (Thread == null || Thread.State == EmulatedThreadState.Terminated)
                    continue;

                bool Self = Instance.CurrentThread != null && Thread.ThreadId == Caller;
                if (Self && SpareCaller)
                    continue;

                if (!Self)
                    Instance.WaitUntilParked(Thread);

                Instance.WinHelper.AbandonMutexesOwnedByThread(Thread.ThreadId);
                Thread.ExitCode = (int)ExitCode;
                Instance.WinHelper.ClearTerminationState(Thread);
                Thread.State = EmulatedThreadState.Terminated;
            }

            Instance.WakeSignal.Bump();
        }
    }
}
