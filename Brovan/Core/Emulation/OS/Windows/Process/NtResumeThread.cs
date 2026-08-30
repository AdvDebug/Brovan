using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtResumeThread : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong ThreadHandle = Instance.WinHelper.GetArg(0);
            ulong PreviousSuspendCountPtr = Instance.WinHelper.GetArg(1);

            EmulatedThread TargetThread = null;
            if (ThreadHandle == 0xFFFFFFFFFFFFFFFEUL)
                TargetThread = Instance.CurrentThread;
            else
                TargetThread = Instance.WinHelper.HandleManager.GetObjectByHandle<EmulatedThread>(ThreadHandle);

            if (TargetThread == null)
            {
                // The initial thread of a spawned process lives in the other emulator, and a process created
                // suspended is still parked there waiting for exactly this call.
                WinRemoteThread Remote = Instance.WinHelper.HandleManager.GetObjectByHandle<WinRemoteThread>(ThreadHandle);
                if (Remote == null)
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                if (Remote.Process == null || Remote.Process.HasExited)
                    return NTSTATUS.STATUS_THREAD_IS_TERMINATING;

                if (PreviousSuspendCountPtr != 0)
                {
                    if (!Instance.IsRegionMapped(PreviousSuspendCountPtr, 4))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    Instance._emulator.WriteMemory(PreviousSuspendCountPtr, 1u);
                }

                // A process that was never held cannot report a failure to release it, and the suspend count
                // still has to come back or the caller treats the whole create as failed.
                Remote.Process.Resume();
                return NTSTATUS.STATUS_SUCCESS;
            }

            if (PreviousSuspendCountPtr != 0)
            {
                if (!Instance.IsRegionMapped(PreviousSuspendCountPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                Instance._emulator.WriteMemory(PreviousSuspendCountPtr, (uint)TargetThread.SuspendCount);
            }

            if (TargetThread.SuspendCount > 0)
                TargetThread.SuspendCount--;

            if (TargetThread.SuspendCount == 0)
            {
                if (TargetThread.State == EmulatedThreadState.Suspended)
                {
                    if (TargetThread.WaitActive)
                        TargetThread.State = EmulatedThreadState.Waiting;
                    else
                        TargetThread.State = EmulatedThreadState.Ready;
                        Instance.WakeSignal.Bump();
                }
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
