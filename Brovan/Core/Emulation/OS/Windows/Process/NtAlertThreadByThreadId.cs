using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtAlertThreadByThreadId : IWinSyscall
    {
        public WinSyscallDomain Domain => WinSyscallDomain.Scheduler;

        internal static EmulatedThread GetTargetThread(BinaryEmulator Instance, uint ThreadId)
        {
            if (Instance == null)
                return null;

            if (Instance.CurrentThread != null && Instance.CurrentThread.ThreadId == ThreadId)
                return Instance.CurrentThread;

            return Instance.Threads.TryGetValue(ThreadId, out EmulatedThread Thread) ? Thread : null;
        }

        internal static NTSTATUS AlertThread(BinaryEmulator Instance, uint ThreadId)
        {
            EmulatedThread TargetThread = GetTargetThread(Instance, ThreadId);
            if (TargetThread == null || TargetThread.State == EmulatedThreadState.Terminated)
                return NTSTATUS.STATUS_INVALID_CID;

            WindowsThreadState State = WinEmulatedThread.GetState(TargetThread);

            // The alert is consumed by the target's next wait or by the wake below, so no epoch bump.
            using RankedLock.Scope SchedulerScope = Instance.SchedulerLock.EnterScope();
            State.AlertByThreadIdPending = true;

            if (State.WaitKind == WindowsWaitKind.Alert && TargetThread.State == EmulatedThreadState.Waiting && Instance.TryWakeWaiter(TargetThread)
                && TargetThread != Instance.CurrentThread)
                Instance.YieldSliceAfterWake(TargetThread);

            return NTSTATUS.STATUS_SUCCESS;
        }

        public NTSTATUS Handle(BinaryEmulator Instance)
        {

            uint ThreadId = (uint)Instance.WinHelper.GetArg(0);
            return AlertThread(Instance, ThreadId);
        }
    }
}
