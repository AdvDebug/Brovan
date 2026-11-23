using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtYieldExecution : IWinSyscall
    {
        public WinSyscallDomain Domain => WinSyscallDomain.Scheduler;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            EmulatedThread Thread = Instance.CurrentThread;
            if (Thread == null)
                return NTSTATUS.STATUS_UNSUCCESSFUL;

            return Yield(Instance, Thread);
        }

        internal static NTSTATUS Yield(BinaryEmulator Instance, EmulatedThread Thread)
        {
            // Without KernelLock the replies wait for the next yield, delay or wait of this thread.
            if (Instance.WinHelper.HasPendingConnectReplies && Instance.KernelLockCovered)
                AlpcMessaging.DeliverConnectReplies(Instance, Thread.ThreadId);

            NTSTATUS Status = Instance.HasThreadReadyForYield() ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_NO_YIELD_PERFORMED;

            // The slice ends also when no thread is ready, because host I/O is served only between slices.
            Thread.State = EmulatedThreadState.Ready;
            Instance._emulator.StopEmulation();
            return Status;
        }
    }
}
