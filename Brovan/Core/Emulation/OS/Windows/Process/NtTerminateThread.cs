using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtTerminateThread : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong ThreadHandle = Instance.WinHelper.GetArg(0);
            ulong ExitStatus = (uint)Instance.WinHelper.GetArg(1);

            bool TerminatingSelfByNullHandle = ThreadHandle == 0;
            EmulatedThread TargetThread = null;
            if (ThreadHandle == 0 || HandleManager.IsCurrentThreadPseudoHandle(ThreadHandle))
                TargetThread = Instance.CurrentThread;
            else
                TargetThread = Instance.WinHelper.HandleManager.GetObjectByHandle<EmulatedThread>(ThreadHandle);

            if (TargetThread == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (TargetThread.State == EmulatedThreadState.Terminated)
                return NTSTATUS.STATUS_SUCCESS;

            if (TerminatingSelfByNullHandle && CountLiveThreads(Instance) <= 1)
                return NTSTATUS.STATUS_CANT_TERMINATE_SELF;

            bool TerminatingSelf = Instance.CurrentThread != null && TargetThread.ThreadId == (uint)Instance.CurrentThreadId;
            using BinaryEmulator.ThreadClaim Claim = TerminatingSelf ? default : Instance.WaitUntilParked(TargetThread);

            End(Instance, TargetThread, (uint)ExitStatus);

            if (TerminatingSelf)
            {
                Instance._emulator.WriteRegister(Instance.IPRegister, 0UL);
                Instance._emulator.StopEmulation();
            }

            if ((Instance.Settings.Flags & LogFlags.General) != 0)
                Instance.TriggerEventMessage($"[{(ExitStatus == 0 ? '+' : '!')}] Thread with ID {TargetThread.ThreadId} was terminated with the status code 0x{ExitStatus:X}", LogFlags.General);

            return NTSTATUS.STATUS_SUCCESS;
        }

        internal static void TerminateOther(BinaryEmulator Instance, EmulatedThread Thread, uint ExitStatus)
        {
            if (Thread.State == EmulatedThreadState.Terminated)
                return;

            using BinaryEmulator.ThreadClaim Claim = Instance.WaitUntilParked(Thread);
            End(Instance, Thread, ExitStatus);
        }

        internal static void End(BinaryEmulator Instance, EmulatedThread Thread, uint ExitStatus, bool ReleaseResources = true)
        {
            Instance.WinHelper.AbandonMutexesOwnedByThread(Thread.ThreadId);

            Thread.ExitCode = unchecked((int)ExitStatus);
            Instance.WinHelper.ClearTerminationState(Thread);
            using (Instance.SchedulerLock.EnterScope())
                Thread.State = EmulatedThreadState.Terminated;
            if (ReleaseResources)
                Instance.WinHelper.ReleaseThreadResources(Thread);
            Instance.WakeSignal.Bump();
        }

        /// <summary>
        /// Counts threads that still represent live execution in the current process.
        /// </summary>
        private static int CountLiveThreads(BinaryEmulator Instance)
        {
            int Count = 0;

            foreach (EmulatedThread Thread in Instance.Threads.Values)
            {
                if (Thread != null && Thread.State != EmulatedThreadState.Terminated)
                    Count++;
            }

            return Count;
        }
    }
}
