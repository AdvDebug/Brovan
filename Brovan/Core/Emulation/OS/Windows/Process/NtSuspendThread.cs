using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtSuspendThread : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            ulong ThreadHandle = Instance.WinHelper.GetArg(0);
            ulong PreviousSuspendCountPtr = Instance.WinHelper.GetArg(1);

            const int MaximumSuspendCount = 0x7F;

            EmulatedThread TargetThread = null;
            if (HandleManager.IsCurrentThreadPseudoHandle(ThreadHandle))
                TargetThread = Instance.CurrentThread;
            else
                TargetThread = Instance.WinHelper.HandleManager.GetObjectByHandle<EmulatedThread>(ThreadHandle);

            if (TargetThread == null)
                return NTSTATUS.STATUS_INVALID_HANDLE;

            if (PreviousSuspendCountPtr != 0 && !Instance.IsRegionMapped(PreviousSuspendCountPtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (TargetThread.State == EmulatedThreadState.Terminated || TargetThread.SuspendCount >= MaximumSuspendCount)
            {
                if (PreviousSuspendCountPtr != 0)
                    Instance.WinHelper.WriteUInt32(PreviousSuspendCountPtr, 0);

                return TargetThread.State == EmulatedThreadState.Terminated
                    ? NTSTATUS.STATUS_THREAD_IS_TERMINATING
                    : NTSTATUS.STATUS_SUSPEND_COUNT_EXCEEDED;
            }

            if (PreviousSuspendCountPtr != 0)
                Instance.WinHelper.WriteUInt32(PreviousSuspendCountPtr, (uint)TargetThread.SuspendCount);

            TargetThread.SuspendCount++;
            TargetThread.State = EmulatedThreadState.Suspended;

            if (Instance.CurrentThread != null && TargetThread.ThreadId == (uint)Instance.CurrentThreadId)
            {
                ulong SyscallRip = Instance.WinHelper.GetSyscallRip(TargetThread, true);
                ulong NextRip = SyscallRip + 2;
                Instance._emulator.WriteRegister(Instance.IPRegister, NextRip);
                Instance._emulator.StopEmulation();
            }
            else
            {
                Instance._emulator.StopThread(TargetThread.ThreadId);
            }

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
