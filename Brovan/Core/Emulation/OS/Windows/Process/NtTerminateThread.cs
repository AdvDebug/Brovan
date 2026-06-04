using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtTerminateThread : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong ThreadHandle = Instance.WinHelper.GetArg64(0);
            ulong ExitStatus = (uint)Instance.WinHelper.GetArg64(1);

            bool TerminatingSelfByNullHandle = ThreadHandle == 0;
            EmulatedThread TargetThread = null;
            if (ThreadHandle == 0 || ThreadHandle == HandleManager.CurrentThread)
                TargetThread = Instance.CurrentThread;
            else
                TargetThread = Instance.WinHelper.HandleManager.GetObjectByHandle<EmulatedThread>(ThreadHandle);

            if (TargetThread == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (TerminatingSelfByNullHandle && CountLiveThreads(Instance) <= 1)
                return NTSTATUS.STATUS_CANT_TERMINATE_SELF;

            Instance.WinHelper.AbandonMutexesOwnedByThread(TargetThread.ThreadId);

            TargetThread.ExitCode = unchecked((int)(uint)ExitStatus);
            TargetThread.State = EmulatedThreadState.Terminated;
            TargetThread.WaitActive = false;
            TargetThread.WaitHandles = null;
            TargetThread.WaitDeadline = -1;
            TargetThread.WaitTimedOut = false;
            TargetThread.WaitSatisfiedIndex = -1;

            WindowsThreadState State = WinEmulatedThread.TryGetState(TargetThread);
            if (State != null)
            {
                State.ApcAlertable = false;
                State.WaitAlertable = false;
                State.WaitCompleted = false;
                State.WaitStatus = NTSTATUS.STATUS_SUCCESS;
                State.WaitResumeRIP = 0;
                State.WaitReturnRIP = 0;
                State.WorkerFactoryWaitActive = false;
                State.AlertByThreadIdWaitActive = false;
            }

            if (Instance.CurrentThread != null && TargetThread.ThreadId == (uint)Instance.CurrentThreadId)
            {
                Instance._emulator.WriteRegister(Instance.IPRegister, 0UL);
                Instance._emulator.StopEmulation();
            }

            Instance.TriggerEventMessage($"[{(ExitStatus == 0 ? '+' : '!')}] Thread with ID {TargetThread.ThreadId} was terminated with the status code 0x{ExitStatus:X}", LogFlags.General);

            return NTSTATUS.STATUS_SUCCESS;
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
