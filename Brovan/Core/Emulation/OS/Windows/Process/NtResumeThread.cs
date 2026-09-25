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
            if (HandleManager.IsCurrentThreadPseudoHandle(ThreadHandle))
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

                uint Previous = Remote.Process == null || Remote.Process.HasExited ? 0u : (uint)Remote.SuspendCount;

                if (PreviousSuspendCountPtr != 0 && !Instance.IsRegionMapped(PreviousSuspendCountPtr, 4))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                // Only the create-suspended hold is known on this side.
                if (Previous == 1)
                {
                    NTSTATUS ResumeStatus = Remote.Process.Resume();
                    if (ResumeStatus != NTSTATUS.STATUS_SUCCESS)
                        return ResumeStatus;
                }

                if (Previous > 0)
                    Remote.SuspendCount--;

                if (PreviousSuspendCountPtr != 0)
                    Instance.WinHelper.WriteUInt32(PreviousSuspendCountPtr, Previous);

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
                    TargetThread.State = TargetThread.WaitActive ? EmulatedThreadState.Waiting : EmulatedThreadState.Ready;
                    Instance.WakeSignal.Bump();
                }
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
